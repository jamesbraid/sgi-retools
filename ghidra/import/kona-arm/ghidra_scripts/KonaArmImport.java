// Build a Ghidra program from a KONA ARM firmware image.
//
// Run as an analyzeHeadless -preScript on a file imported raw:
//
//   analyzeHeadless DIR PROJ -import ucode/KONA/arm1.u -loader BinaryLoader \
//     -processor ARM:BE:32:v4 -preScript KonaArmImport.java [REPO]
//
// REPO is the repository root (default: the working directory); the script
// reads ucode/*.tsv, ucode/tport.md and ghidra/import/kona-arm/tables.tsv from it.
//
// Accepts arm1.u, arm1_kpm.u, tport.bin and the diagnostic images
// diags/IR/ucode/arm1.u, arm1_nic.u and diag_arm_init.u. All are big-endian
// ARM images in AIF layout (ucode/arm1.md); tport.bin puts a 20-byte EEPROM
// file header in front (ucode/tport.md). The processor is ARMv4 big-endian:
// the code uses the v4 halfword transfers and no Thumb or BX.
//
// What it does:
//  - replaces the raw block with the read-only, read-write and zero-init
//    parts at their link addresses, and adds the ARM address map kpm names
//    (ucode/arm1_firmware.md): SRAM (the state block, r8 = 0), the
//    host-interface registers at 0x200000, the payload and next-handler
//    ports at 0x200200, the engine descriptor and data ports at 0x200600,
//    the token map at 0x400000, the display bus, the EEPROM and cache tags;
//  - sets r8 = 0 and r9 = 0x200200 over the code after the start-up sets
//    them, so r9-relative stores resolve to the named ports;
//  - names functions and data from the image's debug table (arm1.u), or,
//    for an image without one, by matching each call target's words against
//    arm1.u with branch and pc-relative offsets masked (the rule of
//    scripts/arm1_disasm.py), then the display-request table and, for
//    tport.bin, the labels of ucode/tport.md;
//  - names every ARM-side register and port from ucode/arm1_registers.tsv;
//  - types the static token list (vector_end) entry by entry, labels each
//    token's slot in it, in icu_map and in the hardware map at 0x400000,
//    and comments each handler with its tokens (ucode/arm1_handlers.tsv,
//    ucode/icu_map.tsv);
//  - lays the documented data tables of ghidra/import/kona-arm/tables.tsv.
//
// @category KONA

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;

public class KonaArmImport extends GhidraScript {

	static final CategoryPath CAT = new CategoryPath("/KONA/arm");

	Path repo;
	byte[] file;
	int hoff, ro, rw, dbg, zi, entryOff;
	long base, dbase;
	AddressSpace ram;
	Memory mem;
	SymbolTable st;
	Listing listing;
	String image;
	// address -> names, first one primary
	TreeMap<Long, List<String>> names = new TreeMap<>();
	Set<Long> funcs = new TreeSet<>();
	Set<Long> dataSyms = new TreeSet<>();

	static int be32(byte[] b, int o) {
		return ((b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
	}

	static long u32(byte[] b, int o) {
		return be32(b, o) & 0xffffffffL;
	}

	Address a(long v) {
		return ram.getAddress(v & 0xffffffffL);
	}

	List<String[]> tsv(String rel) throws IOException {
		List<String[]> out = new ArrayList<>();
		Path p = repo.resolve(rel);
		if (!Files.exists(p)) {
			println("missing " + rel + ": skipped");
			return out;
		}
		for (String l : Files.readAllLines(p)) {
			if (l.isEmpty() || l.startsWith("#")) {
				continue;
			}
			out.add(l.split("\t", -1));
		}
		return out;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		repo = Paths.get(args.length > 0 ? args[0] : System.getProperty("user.dir")).toAbsolutePath();
		Path src = Paths.get(currentProgram.getExecutablePath());
		file = Files.readAllBytes(src);
		image = src.getFileName().toString();
		hoff = be32(file, 0) == 0xbadc0ffe ? 0x14 : 0;
		int[] h = new int[32];
		for (int i = 0; i < 32; i++) {
			h[i] = be32(file, hoff + 4 * i);
		}
		if (h[4] != 0xef000011) {
			throw new IOException(image + ": no AIF header (word 4 is not SWI 0x11)");
		}
		ro = h[5];
		rw = h[6];
		dbg = h[7];
		zi = h[8];
		base = h[10] & 0xffffffffL;
		int amode = h[12];
		// Address-mode bit 8: the read-write part has its own base.
		dbase = (amode & 0x100) != 0 ? h[13] & 0xffffffffL : base + ro;
		// Word 3 is the entry offset in a non-executable image, else a BL.
		entryOff = (h[3] >>> 24) == 0 ? h[3] : 0;
		println(String.format("%s: AIF at 0x%x, RO 0x%x at 0x%08x, RW 0x%x at 0x%08x, ZI 0x%x, debug 0x%x, entry +0x%x",
			image, hoff, ro, base, rw, dbase, zi, dbg, entryOff));

		ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
		mem = currentProgram.getMemory();
		st = currentProgram.getSymbolTable();
		listing = currentProgram.getListing();

		buildMemory();
		readDebugTable();
		if (names.isEmpty() || funcs.isEmpty()) {
			nameByMatch();
		}
		requestTable();
		if (image.equals("tport.bin")) {
			tportLabels();
		}
		registers();
		setBaseRegisters();
		applyNames();
		tables();
		tokenList();
		hardwareMap();
	}

	// ---------------------------------------------------------------- memory

	void buildMemory() throws Exception {
		FileBytes fb = mem.getAllFileBytes().get(0);
		for (MemoryBlock b : mem.getBlocks()) {
			mem.removeBlock(b, monitor);
		}
		MemoryBlock b = mem.createInitializedBlock("ro", a(base), fb, hoff + 0x80, ro, false);
		b.setPermissions(true, false, true);
		b.setComment("read-only part of the AIF image");
		if (rw > 0) {
			b = mem.createInitializedBlock("rw", a(dbase), fb, hoff + 0x80 + ro, rw, false);
			b.setPermissions(true, true, false);
			b.setComment("initialised read-write data");
		}
		if (zi > 0) {
			b = mem.createInitializedBlock("zi", a(dbase + rw), zi, (byte) 0, monitor, false);
			b.setPermissions(true, true, false);
			b.setComment("zero-initialised data");
		}
		// The ARM address map kpm names (ucode/arm1_firmware.md). Sizes are
		// the extent the firmware is seen to use, or the distance to the
		// next named region where it is not.
		region("sram", 0x0, 0x1000, false,
			"HA_SRAM: the ARM's RAM, addressed as r8 + offset (the state block); the stack tops out at 0x1000");
		region("hip", 0x200000, 0x100, true,
			"HA_REG_BASE: host-interface control and status registers (ucode/arm1_registers.tsv)");
		region("hip_data", 0x200200, 0x400, true,
			"HA_DATA, HA_DATA_LAST, HA_DATA_NOPIPE payload ports and the HA_CMD next-handler fetch (r9 + 0 to r9 + 0x3ff)");
		region("ge_ports", 0x200600, 0x600, true,
			"HA_GED_CTRL descriptor and engine-select ports (0x200600) and HA_GED_DATA data ports (0x200a00)");
		region("icu_map_hw", 0x400000, 0x800, true,
			"HA_ICU_MAP: the 512-entry token map the host interface consults for each token");
		region("vcbus", 0x600000, 0x200000, true,
			"HA_VCBUS: the display bus window");
		region("eeprom", 0x800000, 0x200000, true,
			"HA_EEPROM: the board EEPROM window");
		region("cache_tag", 0xa00000, 0x1000, true,
			"HA_CACHE_TAG: the reset code clears every 0x20th byte of this 4 KB window");
		if (dbase > 0x4000000L && dbase < 0xc000000L) {
			region("sdram", 0x4000000L, dbase - 0x4000000L, false, "HA_SDRAM below the image's data");
		}
		else {
			region("sdram", 0x4000000L, 0x1000, false,
				"HA_SDRAM: the first 4 KB only; the image places no data here, so its extent is not shown");
		}
	}

	// Create a block over the parts of [start, start+len) no block covers.
	void region(String name, long start, long len, boolean vol, String comment) throws Exception {
		AddressSet want = new AddressSet(a(start), a(start + len - 1));
		want = want.subtract(mem);
		int k = 0;
		for (AddressRange r : want) {
			String n = k == 0 ? name : name + "_" + k;
			MemoryBlock b = mem.createUninitializedBlock(n, r.getMinAddress(), r.getLength(), false);
			b.setPermissions(true, true, false);
			b.setVolatile(vol);
			b.setComment(comment);
			k++;
		}
	}

	// ----------------------------------------------------------------- names

	void addName(long v, String n) {
		List<String> l = names.computeIfAbsent(v, x -> new ArrayList<>());
		if (!l.contains(n)) {
			l.add(n);
		}
	}

	// Data in the read-only part that carries a code symbol (ucode/arm1.md,
	// ucode/arm1_firmware.md, ucode/arm1_functions.md).
	static final Set<String> RO_DATA = new HashSet<>(Arrays.asList(
		"vector_start", "vector_end", "hipctl", "hipwc", "EdgeDescArray"));

	void readDebugTable() {
		if (dbg == 0) {
			return;
		}
		int d = file.length - dbg;
		int n = be32(file, d + 32);
		int tab = d + 36, strs = tab + 8 * n;
		long roEnd = base + ro;
		for (int k = 0; k < n; k++) {
			int f = be32(file, tab + 8 * k);
			long v = u32(file, tab + 8 * k + 4);
			int o = strs + (f & 0xffffff), e = o;
			while (file[e] != 0) {
				e++;
			}
			String nm = new String(file, o, e - o, java.nio.charset.StandardCharsets.ISO_8859_1);
			int flags = f >>> 24;
			addName(v, nm);
			// Flags 2 and 3 mark read-only symbols, 4 to 7 data, 1 linker
			// region marks. A read-only symbol starts a function unless it
			// is a region mark, an area name or a documented table.
			boolean code = (flags == 2 || flags == 3) && v >= base && v < roEnd;
			if (code && !nm.contains("$") && !nm.equals("ucode") && !RO_DATA.contains(nm)) {
				funcs.add(v);
			}
			else if (flags != 1 && !nm.contains("$")) {
				dataSyms.add(v);
			}
		}
		// A plain name wins over a region mark at the same address.
		for (List<String> l : names.values()) {
			l.sort(Comparator.comparing((String s) -> s.contains("$") || s.equals("ucode") ? 1 : 0));
		}
		println(String.format("debug table: %d symbols, %d functions", n, funcs.size()));
	}

	static int maskWord(int i) {
		if (((i >>> 25) & 7) == 5) {
			return i & 0xff000000;
		}
		if (((i >>> 26) & 3) == 1 && ((i >>> 16) & 15) == 15) {
			return i & 0xfffff000;
		}
		if (((i >>> 26) & 3) == 0 && ((i >>> 16) & 15) == 15 && ((i >>> 25) & 1) == 1) {
			return i & 0xfffff000;
		}
		return i;
	}

	// Name the call targets of an image without symbols by arm1.u's masked
	// words (scripts/arm1_disasm.py --tport); the rest become fn_<address>.
	void nameByMatch() throws IOException {
		Path ref = repo.resolve("root/usr/gfx/ucode/KONA/arm1.u");
		Map<Long, int[]> sigs = new HashMap<>();
		Map<Long, String> refNames = new HashMap<>();
		Map<Integer, List<Long>> byHead = new HashMap<>();
		if (Files.exists(ref)) {
			byte[] r = Files.readAllBytes(ref);
			int rro = be32(r, 0x14), rdbg = be32(r, 0x1c);
			long rbase = u32(r, 0x28);
			int d = r.length - rdbg, n = be32(r, d + 32), tab = d + 36, strs = tab + 8 * n;
			TreeMap<Long, String> fn = new TreeMap<>();
			for (int k = 0; k < n; k++) {
				int f = be32(r, tab + 8 * k);
				long v = u32(r, tab + 8 * k + 4);
				if (v < rbase || v >= rbase + rro) {
					continue;
				}
				int o = strs + (f & 0xffffff), e = o;
				while (r[e] != 0) {
					e++;
				}
				fn.putIfAbsent(v, new String(r, o, e - o, java.nio.charset.StandardCharsets.ISO_8859_1));
			}
			// Ties at one address keep the first name in table order, as
			// the Python script's sorted symbol list does.
			List<Long> keys = new ArrayList<>(fn.keySet());
			for (int k = 0; k < keys.size(); k++) {
				long v = keys.get(k), end = k + 1 < keys.size() ? keys.get(k + 1) : rbase + rro;
				if (end - v < 16) {
					continue;
				}
				int[] w = new int[(int) ((end - v) / 4)];
				for (int i = 0; i < w.length; i++) {
					w[i] = maskWord(be32(r, 0x80 + (int) (v - rbase) + 4 * i));
				}
				sigs.put(v, w);
				refNames.put(v, fn.get(v));
				byHead.computeIfAbsent(w[0] ^ (w[1] * 31) ^ (w[2] * 961) ^ (w[3] * 29791), x -> new ArrayList<>()).add(v);
			}
		}
		else {
			println("root/usr/gfx/ucode/KONA/arm1.u missing: call targets stay fn_<address>");
		}
		TreeSet<Long> targets = new TreeSet<>();
		for (int o = 0; o < ro; o += 4) {
			int i = be32(file, hoff + 0x80 + o);
			if (((i >>> 24) & 15) == 11) {
				int off = i & 0xffffff;
				if ((off & 0x800000) != 0) {
					off -= 0x1000000;
				}
				long t = base + o + 8 + 4L * off;
				if (t >= base && t < base + ro) {
					targets.add(t);
				}
			}
		}
		int matched = 0;
		for (long t : targets) {
			int off = (int) (t - base);
			int[] head = new int[4];
			for (int k = 0; k < 4; k++) {
				head[k] = off + 4 * k < ro ? maskWord(be32(file, hoff + 0x80 + off + 4 * k)) : 0;
			}
			String nm = null;
			List<Long> cands = byHead.getOrDefault(head[0] ^ (head[1] * 31) ^ (head[2] * 961) ^ (head[3] * 29791),
				Collections.emptyList());
			cands = new ArrayList<>(cands);
			Collections.sort(cands);
			for (long c : cands) {
				int[] w = sigs.get(c);
				boolean ok = true;
				for (int k = 0; k < w.length && ok; k++) {
					int q = off + 4 * k;
					ok = q < ro && maskWord(be32(file, hoff + 0x80 + q)) == w[k];
				}
				if (ok) {
					nm = refNames.get(c);
					break;
				}
			}
			if (nm != null) {
				matched++;
			}
			addName(t, nm != null ? nm : String.format("fn_%08x", t));
			funcs.add(t);
		}
		println(String.format("no symbols: %d call targets, %d named from arm1.u", targets.size(), matched));
	}

	String cstr(long addr) throws MemoryAccessException {
		StringBuilder sb = new StringBuilder();
		for (int k = 0; k < 64; k++) {
			Address ad = a(addr + k);
			if (!mem.contains(ad)) {
				return null;
			}
			byte c = mem.getByte(ad);
			if (c == 0) {
				return sb.toString();
			}
			sb.append((char) (c & 0xff));
		}
		return null;
	}

	long rd(long addr) throws MemoryAccessException {
		return mem.getInt(a(addr)) & 0xffffffffL;
	}

	boolean inRo(long v) {
		return v >= base && v < base + ro;
	}

	long reqTable = -1;
	int reqStride = 0, reqCount = 0;

	// The display-request table: arm1.u's DGDispatchTable {count, handler},
	// or in an image without symbols the {name, count, handler} table that
	// starts with the request "Test" (scripts/arm1_disasm.py --tport).
	void requestTable() throws Exception {
		for (Map.Entry<Long, List<String>> e : names.entrySet()) {
			if (e.getValue().contains("DGDispatchTable")) {
				reqTable = e.getKey();
				reqStride = 8;
			}
		}
		if (reqTable < 0 && rw > 0) {
			for (long p = dbase; p + 12 <= dbase + rw; p += 4) {
				long np = rd(p);
				if (np >= dbase && "Test".equals(cstr(np)) && rd(p + 4) == 1 && inRo(rd(p + 8))) {
					reqTable = p;
					reqStride = 12;
					break;
				}
			}
		}
		if (reqTable < 0) {
			return;
		}
		// Request names come from the table itself (12-byte entries) or, for
		// arm1.u, from the handler symbols already named DoDGRqst*.
		for (int k = 0;; k++) {
			long p = reqTable + (long) reqStride * k;
			if (reqStride == 8) {
				// 93 requests (ucode/arm1_firmware.md, dg_dispatch.tsv).
				if (k == 93) {
					break;
				}
			}
			else {
				if (!inRo(rd(p + 8)) || cstr(rd(p)) == null) {
					break;
				}
				long hnd = rd(p + 8);
				String nm = "DoDGRqst" + cstr(rd(p));
				List<String> l = names.get(hnd);
				if (l == null || l.get(0).startsWith("fn_")) {
					names.put(hnd, new ArrayList<>(List.of(nm)));
				}
				funcs.add(hnd);
			}
			reqCount = k + 1;
		}
		addName(reqTable, reqStride == 8 ? "DGDispatchTable" : "dg_request_table");
		println(String.format("display-request table at 0x%08x, %d entries of %d bytes", reqTable, reqCount, reqStride));
	}

	// Labels of ucode/tport.md's "Unnamed functions" table, for the call
	// targets the arm1.u match leaves as fn_<address>.
	void tportLabels() throws IOException {
		Path md = repo.resolve("ucode/tport.md");
		if (!Files.exists(md)) {
			return;
		}
		int k = 0;
		for (String l : Files.readAllLines(md)) {
			if (!l.startsWith("| 0x0c")) {
				continue;
			}
			String[] c = l.split("\\|");
			long v = Long.decode(c[1].trim());
			String nm = c[2].trim().replace("`", "");
			boolean data = nm.endsWith("(data)");
			nm = nm.replace("(data)", "").trim();
			List<String> cur = names.get(v);
			if (data) {
				funcs.remove(v);
				dataSyms.add(v);
				names.put(v, new ArrayList<>(List.of(nm)));
			}
			else if (cur == null || cur.get(0).startsWith("fn_")) {
				names.put(v, new ArrayList<>(List.of(nm)));
				funcs.add(v);
			}
			else {
				addName(v, nm);
			}
			k++;
		}
		println("labels from ucode/tport.md: " + k);
	}

	void applyNames() throws Exception {
		int nf = 0;
		for (Map.Entry<Long, List<String>> e : names.entrySet()) {
			Address ad = a(e.getKey());
			if (!mem.contains(ad)) {
				continue;
			}
			boolean first = true;
			for (String n : e.getValue()) {
				st.createLabel(ad, n, SourceType.IMPORTED);
				if (first) {
					Symbol s = st.getSymbol(n, ad, null);
					if (s != null) {
						s.setPrimary();
					}
					first = false;
				}
			}
		}
		// Entry points: the reset word and the AIF entry.
		st.addExternalEntryPoint(a(base));
		if (entryOff != 0) {
			st.addExternalEntryPoint(a(base + entryOff));
			if (!funcs.contains(base + entryOff) && !names.containsKey(base + entryOff)) {
				funcs.add(base + entryOff);
			}
		}
		funcs.add(base);
		AddressSet starts = new AddressSet();
		for (long v : funcs) {
			starts.add(a(v));
		}
		new DisassembleCommand(starts, null, true).applyTo(currentProgram, monitor);
		for (long v : funcs) {
			Address ad = a(v);
			if (getFunctionAt(ad) == null) {
				Function f = createFunction(ad, null);
				if (f != null) {
					nf++;
				}
			}
		}
		println(String.format("functions created: %d of %d starts", nf, funcs.size()));
	}

	// ------------------------------------------------------------- registers

	// Register and field records from kpm's ARM-side table. Kind 1 is a
	// register (or, at offset 0xdeadbeef, a layout), kind 2 a field of the
	// record above it. Each record becomes a 32-bit structure of bitfields.
	Map<String, DataType> regTypes = new LinkedHashMap<>();

	void registers() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		List<String[]> rows = tsv("ucode/arm1_registers.tsv");
		String cur = null;
		long curOff = 0;
		Map<String, List<String[]>> fields = new LinkedHashMap<>();
		Map<String, Long> offs = new LinkedHashMap<>();
		for (String[] r : rows) {
			if (r.length < 6 || r[0].equals("vaddr")) {
				continue;
			}
			if (r[1].equals("1")) {
				cur = r[3];
				curOff = Long.decode(r[2]);
				offs.put(cur, curOff);
				fields.put(cur, new ArrayList<>());
			}
			else if (cur != null) {
				fields.get(cur).add(r);
			}
		}
		Set<String> regions = new HashSet<>(Arrays.asList("HA_SRAM", "HA_REG_BASE", "HA_ICU_MAP", "HA_VCBUS",
			"HA_EEPROM", "HA_CACHE_TAG", "HA_CACHE_DATA", "HA_SDRAM", "HA_CACHE_DATA_REVB", "HA_ICACHE"));
		int nl = 0, nt = 0;
		Set<Long> typed = new HashSet<>();
		for (Map.Entry<String, Long> e : offs.entrySet()) {
			String nm = e.getKey();
			long off = e.getValue();
			DataType dt = UnsignedIntegerDataType.dataType;
			if (!fields.get(nm).isEmpty()) {
				StructureDataType s = new StructureDataType(CAT, nm, 4, dtm);
				for (String[] f : fields.get(nm)) {
					long m = Long.decode(f[4]);
					int sh = Integer.parseInt(f[5]);
					int w = Long.bitCount(m);
					if (w == 0 || (m >>> sh) != ((1L << w) - 1)) {
						println("field " + f[3] + " of " + nm + ": mask not contiguous, left out");
						continue;
					}
					try {
						s.insertBitFieldAt(0, 4, sh, UnsignedIntegerDataType.dataType, w, f[3], null);
					}
					catch (Exception x) {
						println("field " + f[3] + " of " + nm + ": " + x.getMessage());
					}
				}
				dt = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
				nt++;
			}
			regTypes.put(nm, dt);
			if (off == 0xdeadbeefL || regions.contains(nm)) {
				continue;
			}
			Address ad = a(off);
			if (!mem.contains(ad)) {
				continue;
			}
			addName(off, nm);
			nl++;
			// The first record at an address (HIP1 before HIP2) types it.
			if (typed.add(off)) {
				try {
					lay(ad, dt, 4, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				}
				catch (CodeUnitInsertionException x) {
					println(nm + ": " + x.getMessage());
				}
			}
		}
		// The descriptor and data ports decode their address (HA_GED_CTRL_ADDR:
		// bits 2-5 select, bits 6-8 tag; HA_GED_DATA_ADDR: bits 6-8 tag).
		for (int tag = 0; tag < 8; tag++) {
			for (int sel = 0; sel < 16; sel++) {
				long ad = 0x200600L + (tag << 6) + (sel << 2);
				if (ad != 0x200600L) {
					addName(ad, String.format("HA_GED_CTRL_T%d_S%d", tag, sel));
				}
			}
			if (tag != 0) {
				addName(0x200a00L + (tag << 6), String.format("HA_GED_DATA_T%d", tag));
			}
		}
		println(String.format("registers: %d labelled, %d bitfield types", nl, nt));
	}

	// r8 and r9 are set once at start-up and never change (ucode/arm1_firmware.md,
	// "What the ARM sees"). Set them for the code that follows the sequence
	// mov r8,#0; mov r9,#0x200000; add r9,r9,#0x200.
	void setBaseRegisters() throws Exception {
		Register r8 = currentProgram.getRegister("r8"), r9 = currentProgram.getRegister("r9");
		ProgramContext pc = currentProgram.getProgramContext();
		for (int o = 0; o + 12 <= ro; o += 4) {
			int p = hoff + 0x80 + o;
			if (be32(file, p) == 0xe3a08000 && be32(file, p + 4) == 0xe3a99602 && be32(file, p + 8) == 0xe2899c02) {
				Address s = a(base + o + 12), e = a(base + ro - 1);
				pc.setValue(r8, s, e, BigInteger.ZERO);
				pc.setValue(r9, s, e, BigInteger.valueOf(0x200200));
				println(String.format("r8 = 0, r9 = 0x200200 from 0x%08x", base + o + 12));
				return;
			}
		}
		println("no r8/r9 start-up sequence: base registers left unset");
	}

	// ---------------------------------------------------------------- tables

	// Lay data over whatever the disassembler left there.
	Data lay(Address ad, DataType dt, int len, DataUtilities.ClearDataMode mode) throws Exception {
		listing.clearCodeUnits(ad, ad.add(len - 1), false);
		return DataUtilities.createData(currentProgram, ad, dt, len, mode);
	}

	// ghidra/import/kona-arm/tables.tsv: image, symbol or address, type, count, source.
	void tables() throws Exception {
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		StructureDataType disp = new StructureDataType(CAT, "dg_dispatch8", 0, dtm);
		disp.add(UnsignedIntegerDataType.dataType, "words", "payload word count");
		disp.add(new PointerDataType(VoidDataType.dataType, 4, dtm), "handler", null);
		StructureDataType req = new StructureDataType(CAT, "dg_request12", 0, dtm);
		req.add(new PointerDataType(CharDataType.dataType, 4, dtm), "name", null);
		req.add(UnsignedIntegerDataType.dataType, "words", "payload word count");
		req.add(new PointerDataType(VoidDataType.dataType, 4, dtm), "handler", null);
		Map<String, DataType> types = new HashMap<>();
		types.put("u8", ByteDataType.dataType);
		types.put("u16", WordDataType.dataType);
		types.put("u32", UnsignedIntegerDataType.dataType);
		types.put("dg_dispatch8", dtm.addDataType(disp, DataTypeConflictHandler.REPLACE_HANDLER));
		types.put("dg_request12", dtm.addDataType(req, DataTypeConflictHandler.REPLACE_HANDLER));
		types.put("icu_entry", regTypes.getOrDefault("HA_ICU_MAP_N", UnsignedIntegerDataType.dataType));
		int n = 0;
		for (String[] r : tsv("ghidra/import/kona-arm/tables.tsv")) {
			if (r[0].equals("image") || !(r[0].equals(image) || r[0].equals("*"))) {
				continue;
			}
			long ad = -1;
			if (r[1].startsWith("0x")) {
				ad = Long.decode(r[1]);
			}
			else if (r[1].equals("@request_table")) {
				ad = reqTable;
			}
			else {
				for (Map.Entry<Long, List<String>> e : names.entrySet()) {
					if (e.getValue().contains(r[1])) {
						ad = e.getKey();
					}
				}
			}
			if (ad < 0 || !mem.contains(a(ad))) {
				continue;
			}
			DataType t = types.get(r[2]);
			int cnt = r[3].equals("@request_count") ? reqCount : Integer.decode(r[3]);
			if (t == null || cnt <= 0) {
				println("tables.tsv: " + r[1] + ": unknown type " + r[2]);
				continue;
			}
			ArrayDataType arr = new ArrayDataType(t, cnt, t.getLength(), dtm);
			lay(a(ad), arr, arr.getLength(),
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			if (r.length > 4 && !r[4].isEmpty()) {
				listing.setComment(a(ad), CommentType.PLATE, r[4]);
			}
			n++;
		}
		println("data tables laid: " + n);
	}

	// ---------------------------------------------------------- token list

	Map<Integer, String> tokName = new HashMap<>();
	Map<Integer, String[]> handlerRow = new HashMap<>();

	// The static list init_hip builds the token map from (ucode/arm1.md,
	// "The token map"): an odd word is a whole routed entry; an even word is
	// followed by the handler address. 0xffffffff ends it.
	void tokenList() throws Exception {
		for (String[] r : tsv("ucode/icu_map.tsv")) {
			if (r[0].startsWith("0x")) {
				tokName.put(Integer.decode(r[0]), r[1]);
			}
		}
		for (String[] r : tsv("ucode/arm1_handlers.tsv")) {
			if (r[0].startsWith("0x")) {
				handlerRow.put(Integer.decode(r[0]), r);
			}
		}
		Long list = null;
		for (Map.Entry<Long, List<String>> e : names.entrySet()) {
			if (e.getValue().contains("vector_end")) {
				list = e.getKey();
			}
		}
		if (list == null) {
			return;
		}
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataType a32 = regTypes.getOrDefault("HA_ICU_MAP_A", UnsignedIntegerDataType.dataType);
		DataType g32 = regTypes.getOrDefault("HA_ICU_MAP_G", UnsignedIntegerDataType.dataType);
		DataType n32 = regTypes.getOrDefault("HA_ICU_MAP_N", UnsignedIntegerDataType.dataType);
		StructureDataType armEnt = new StructureDataType(CAT, "icu_list_arm", 0, dtm);
		armEnt.add(UnsignedIntegerDataType.dataType, "flags", "entry bits 0-3; the map entry is flags | handler << 4");
		armEnt.add(new PointerDataType(VoidDataType.dataType, 4, dtm), "handler", null);
		DataType armT = dtm.addDataType(armEnt, DataTypeConflictHandler.REPLACE_HANDLER);
		Map<Long, List<String>> byHandler = new TreeMap<>();
		long p = list;
		int tok = 0, nArm = 0;
		while (true) {
			long w = rd(p);
			if (w == 0xffffffffL) {
				lay(a(p), UnsignedIntegerDataType.dataType, 4,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				listing.setComment(a(p), CommentType.EOL, "end of the token list");
				break;
			}
			String tn = tokName.getOrDefault(tok, "");
			String lbl = String.format("icu_list_%03x%s", tok, tn.isEmpty() ? "" : "_" + tn);
			st.createLabel(a(p), lbl, SourceType.IMPORTED);
			if ((w & 1) == 0) {
				long hnd = rd(p + 4);
				lay(a(p), armT, 8, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				listing.setComment(a(p), CommentType.EOL, String.format("token 0x%03x %s: ARM handler", tok, tn));
				byHandler.computeIfAbsent(hnd, x -> new ArrayList<>()).add(String.format("0x%03x %s", tok, tn));
				currentProgram.getReferenceManager().addMemoryReference(a(p + 4), a(hnd), RefType.DATA,
					SourceType.IMPORTED, 0);
				p += 8;
				nArm++;
			}
			else {
				boolean geom = (w >>> 31) != 0, regpix = (w & 0x20) != 0;
				lay(a(p), geom ? g32 : n32, 4,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				listing.setComment(a(p), CommentType.EOL, String.format("token 0x%03x %s: routed, %s form, command %d",
					tok, tn, geom ? "geometry" : regpix ? "register/pixel" : "pass", (w >>> 15) & 0x1ff));
				p += 4;
			}
			tok++;
		}
		for (Map.Entry<Long, List<String>> e : byHandler.entrySet()) {
			StringBuilder sb = new StringBuilder("Host token handler for ");
			sb.append(String.join(", ", e.getValue()));
			for (String t : e.getValue()) {
				String[] r = handlerRow.get(Integer.decode(t.split(" ")[0]));
				if (r != null && r.length > 4) {
					sb.append("\ngroup: ").append(r[4]);
					break;
				}
			}
			Address ad = a(e.getKey());
			if (getFunctionAt(ad) == null) {
				new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
				createFunction(ad, null);
			}
			listing.setComment(ad, CommentType.PLATE, sb.toString());
		}
		println(String.format("token list at 0x%08x: %d tokens, %d ARM-run, %d handlers", list, tok, nArm,
			byHandler.size()));
		// icu_map in RAM: init_hip's copy of the entries.
		for (Map.Entry<Long, List<String>> e : names.entrySet()) {
			if (e.getValue().contains("icu_map")) {
				long m = e.getKey();
				for (int t = 0; t < 512; t++) {
					String tn = tokName.getOrDefault(t, "");
					st.createLabel(a(m + 4L * t), String.format("icu_map_%03x%s", t, tn.isEmpty() ? "" : "_" + tn),
						SourceType.IMPORTED);
				}
			}
		}
	}

	// HA_ICU_MAP at 0x400000: one entry per token.
	void hardwareMap() throws Exception {
		Address m = a(0x400000);
		if (!mem.contains(m)) {
			return;
		}
		DataType n32 = regTypes.getOrDefault("HA_ICU_MAP_N", UnsignedIntegerDataType.dataType);
		for (int t = 0; t < 512; t++) {
			String tn = tokName.getOrDefault(t, "");
			st.createLabel(m.add(4L * t), String.format("ICU_MAP_%03x%s", t, tn.isEmpty() ? "" : "_" + tn),
				SourceType.IMPORTED);
		}
		lay(m, new ArrayDataType(n32, 512, 4), 2048,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
	}
}
