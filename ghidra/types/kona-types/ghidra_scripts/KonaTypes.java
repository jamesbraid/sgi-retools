// Add the documented KONA structures to a program and apply them where
// their address is fixed.
//
// Run as an analyzeHeadless -postScript (after analysis) on any import:
//
//   analyzeHeadless DIR PROJ -process PROGRAM -noanalysis \
//     -scriptPath ghidra/types/kona-types/ghidra_scripts -postScript KonaTypes.java [REPO]
//
// REPO is the repository root (default: the working directory). Types, all
// under /KONA/types, built from the repository's own records:
//
//   kona_arm_state       the ARM firmware's state block (SRAM at r8 = 0),
//                        from ghidra/types/kona-types/arm_state.tsv
//   kona_vertex_record   the geometry engines' vertex record, from
//                        ghidra/types/kona-types/vertex_record.tsv
//   kona_entry_geom,     a routed token-map entry in its three forms, with
//   kona_entry_pass,     the distributor control word split as ucode/ged.md
//   kona_entry_regpix    decodes it
//   kona_ge_special      enum of the geometry-engine special registers (GE.h)
//   kona_hh_reg          enum of the host-interface registers at their
//                        kernel window offset 0x800000 + register (HIP.h)
//
// Applied:
//   - ARM firmware (an import by ghidra/import/kona-arm, with its "sram" block):
//     kona_arm_state at SRAM 0 in the production arm1.u, whose layout the
//     state block rows describe; each routed entry of the token list typed
//     in its form.
//   - Kernel objects (MIPS): every call to gfx_pio_read_32/64 or
//     gfx_pio_write_32/64 whose address the decompiler folds to a base plus
//     0x800000 + register (or the 0xc00000 alias) gets the register's name
//     as an end-of-line comment, and a line of the log.
//   - Anything else: the types only. The vertex record and the special
//     registers have no fixed address in any image: the engines reach the
//     record through address registers, and the special-register address
//     is an inference (GE.h).
//
// @category KONA

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;

public class KonaTypes extends GhidraScript {

	static final CategoryPath CAT = new CategoryPath("/KONA/types");
	Path repo;
	DataTypeManager dtm;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		repo = Paths.get(args.length > 0 ? args[0] : System.getProperty("user.dir")).toAbsolutePath();
		dtm = currentProgram.getDataTypeManager();
		DataType state = recordType("ghidra/types/kona-types/arm_state.tsv", "kona_arm_state", 1, 0x1000);
		recordType("ghidra/types/kona-types/vertex_record.tsv", "kona_vertex_record", 4, 0);
		DataType[] forms = entryTypes();
		enumFromHeader("GE.h", "kona_ge_special", "KONA_GE11_SR_(\\w+)", null, 0, 1);
		EnumDataType hh = enumFromHeader("HIP.h", "kona_hh_reg",
			"KONA_((?:HIP[12]_)?HH_\\w+)", "register mask", 0x800000, 4);
		println("types added under " + CAT);

		String proc = currentProgram.getLanguage().getProcessor().toString();
		Memory mem = currentProgram.getMemory();
		if (proc.equals("ARM") && mem.getBlock("sram") != null) {
			applyArm(state, forms);
		}
		else if (proc.equals("MIPS")) {
			applyKernel(hh);
		}
	}

	// ------------------------------------------------------------- records

	List<String[]> tsv(String rel) throws IOException {
		List<String[]> out = new ArrayList<>();
		for (String l : Files.readAllLines(repo.resolve(rel))) {
			if (l.isEmpty() || l.startsWith("#") || l.startsWith("offset\t")) {
				continue;
			}
			out.add(l.split("\t", -1));
		}
		return out;
	}

	DataType base(String t) {
		switch (t) {
			case "u8":
				return ByteDataType.dataType;
			case "u16":
				return WordDataType.dataType;
			case "u32":
				return UnsignedIntegerDataType.dataType;
			case "float":
				return Float4DataType.dataType;
			case "ptr":
				return new PointerDataType(VoidDataType.dataType, 4, dtm);
		}
		throw new IllegalArgumentException("type " + t);
	}

	DataType fieldType(String t) {
		Matcher m = Pattern.compile("(\\w+)\\[(\\d+)\\]").matcher(t);
		if (m.matches()) {
			DataType b = base(m.group(1));
			return new ArrayDataType(b, Integer.parseInt(m.group(2)), b.getLength(), dtm);
		}
		return base(t);
	}

	// A structure from offset/type/name/status/source rows. Offsets are in
	// units of `unit` bytes; rows sharing an offset become a union there.
	// size 0 means: end at the last field.
	DataType recordType(String rel, String name, int unit, int size) throws Exception {
		TreeMap<Integer, List<String[]>> rows = new TreeMap<>();
		for (String[] r : tsv(rel)) {
			rows.computeIfAbsent(Integer.decode(r[0]) * unit, x -> new ArrayList<>()).add(r);
		}
		StructureDataType s = new StructureDataType(CAT, name, size, dtm);
		for (Map.Entry<Integer, List<String[]>> e : rows.entrySet()) {
			List<String[]> rs = e.getValue();
			if (rs.size() == 1) {
				String[] r = rs.get(0);
				DataType t = fieldType(r[1]);
				put(s, e.getKey(), t, r[2], r[3] + ": " + r[4]);
			}
			else {
				UnionDataType u = new UnionDataType(CAT, name + "_" + String.format("%x", e.getKey()), dtm);
				for (String[] r : rs) {
					u.add(fieldType(r[1]), r[2], r[3] + ": " + r[4]);
				}
				put(s, e.getKey(), dtm.addDataType(u, DataTypeConflictHandler.REPLACE_HANDLER), "u_" + rs.get(0)[2],
					"one of: " + rs.stream().map(r -> r[2]).reduce((a, b) -> a + ", " + b).get());
			}
		}
		s.setDescription("Built from " + rel + "; undefined bytes are not documented.");
		return dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	static void put(StructureDataType s, int off, DataType t, String name, String comment) {
		if (s.getLength() < off + t.getLength()) {
			s.growStructure(off + t.getLength() - s.getLength());
		}
		s.replaceAtOffset(off, t, t.getLength(), name, comment);
	}

	// ----------------------------------------------- token-map entry forms

	// Field lists: {lsb, width, name}. Bits 0-5 are the host-interface fields
	// kpm names (ucode/arm1.md); the rest follow ucode/ged.md "The token-map
	// entry is the distributor's control word". Meanings marked inferred
	// there stay inferred; the comment says so.
	static final Object[][] COMMON = {
		{ 0, 1, "dh", "1: routed by the hardware (ICU_MAP_DH)" },
		{ 1, 2, "bgnend", "kind: 0 any, 1 begin, 2 end, 3 legal inside begin/end (inferred)" },
		{ 3, 1, "next", "chain bit (ICU_MAP_NEXT)" },
		{ 4, 1, "datainv", "counted words are not data (ICU_MAP_DATAINV; inferred meaning)" },
		{ 5, 1, "cmdval", "1 in the register/pixel form (ICU_MAP_CMDVAL)" },
	};
	static final Object[][] GEOM = {
		{ 6, 3, "count", "payload word count (ICU_MAP_G_WC)" },
		{ 9, 5, "attr_offset", "control 1-5: word of the attribute in the vertex record (inferred)" },
		{ 14, 1, "vertex_data", "control 6: the payload is vertex data (inferred)" },
		{ 15, 6, "k", "control 7-12: the entry number k" },
		{ 21, 1, "vertex", "control 13: completes a vertex (inferred)" },
		{ 22, 1, "is_float", "control 14: data are floating point (inferred)" },
		{ 23, 1, "is_unsigned", "control 15: data are unsigned (inferred)" },
		{ 24, 1, "normalise", "control 16: integer data are normalised (inferred)" },
		{ 25, 2, "missing", "control 17-18: 4 minus the component count (inferred)" },
		{ 27, 2, "last_bytes", "control 19-20: valid bytes in the last word minus 1 (inferred)" },
		{ 29, 2, "size", "control 21-22: component size 0 byte, 1 short, 2 32-bit, 3 double (inferred)" },
		{ 31, 1, "gfx", "1: geometry form (ICU_MAP_GFX)" },
	};
	static final Object[][] PASS = {
		{ 6, 5, "count", "payload word count, 0 meaning 32 (ICU_MAP_N_WC)" },
		{ 11, 4, "ctrl_3_6", "control bits 3-6" },
		{ 15, 9, "command", "9-bit command number; bits 6-8 of it are control bits 13-15 (ucode/arm1.md, ucode/ged.md)" },
		{ 24, 7, "ctrl_16_22", "control bits 16-22" },
		{ 31, 1, "gfx", "0: not the geometry form" },
	};
	static final Object[][] REGPIX = {
		{ 6, 5, "count", "payload word count, 0 meaning 32 (ICU_MAP_N_WC)" },
		{ 11, 10, "ctrl_3_12", "control bits 3-12" },
		{ 21, 10, "reg", "control 13-22: distributor register" },
		{ 31, 1, "gfx", "0: not the geometry form" },
	};

	DataType[] entryTypes() throws Exception {
		Object[][][] lists = { GEOM, PASS, REGPIX };
		String[] names = { "kona_entry_geom", "kona_entry_pass", "kona_entry_regpix" };
		DataType[] out = new DataType[3];
		for (int i = 0; i < 3; i++) {
			StructureDataType s = new StructureDataType(CAT, names[i], 4, dtm);
			for (Object[][] l : new Object[][][] { COMMON, lists[i] }) {
				for (Object[] f : l) {
					s.insertBitFieldAt(0, 4, (Integer) f[0], UnsignedIntegerDataType.dataType, (Integer) f[1],
						(String) f[2], (String) f[3]);
				}
			}
			out[i] = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		return out;
	}

	// An enum from "#define PREFIX_NAME 0xVALUE" lines of a repository header,
	// optionally only the lines that carry the text `need`.
	EnumDataType enumFromHeader(String hdr, String name, String re, String need, long add, int size) throws Exception {
		EnumDataType e = new EnumDataType(CAT, name, size, dtm);
		Pattern p = Pattern.compile("^#define\\s+" + re + "\\s+(0x[0-9a-fA-F]+)\\b");
		for (String l : Files.readAllLines(repo.resolve(hdr))) {
			Matcher m = p.matcher(l);
			if (m.find() && !m.group(1).endsWith("_MASK") && (need == null || l.contains(need))) {
				long v = Long.decode(m.group(2)) + add;
				if (e.contains(m.group(1))) {
					continue;
				}
				e.add(m.group(1), v);
			}
		}
		dtm.addDataType(e, DataTypeConflictHandler.REPLACE_HANDLER);
		println(String.format("%s: %d names from %s", name, e.getCount(), hdr));
		return e;
	}

	// ------------------------------------------------------------- ARM

	void applyArm(DataType state, DataType[] forms) throws Exception {
		Listing listing = currentProgram.getListing();
		SymbolTable st = currentProgram.getSymbolTable();
		Memory mem = currentProgram.getMemory();
		// The state block rows read arm1.u 6.5.30m; other images keep other
		// layouts (tport.bin's records are shifted, ucode/tport.md).
		boolean prod = !st.getGlobalSymbols("arm_cullface").isEmpty() && !st.getGlobalSymbols("init_hip").isEmpty();
		if (prod) {
			Address z = mem.getBlock("sram").getStart();
			listing.clearCodeUnits(z, z.add(state.getLength() - 1), false);
			DataUtilities.createData(currentProgram, z, state, state.getLength(),
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			st.createLabel(z, "arm_state", SourceType.IMPORTED);
			println("kona_arm_state laid at SRAM 0");
		}
		int n = 0;
		SymbolIterator it = st.getSymbolIterator("icu_list_*", true);
		for (Symbol s : it) {
			Address ad = s.getAddress();
			long w = mem.getInt(ad) & 0xffffffffL;
			if ((w & 1) == 0 || w == 0xffffffffL) {
				continue;
			}
			DataType t = (w >>> 31) != 0 ? forms[0] : (w & 0x20) != 0 ? forms[2] : forms[1];
			listing.clearCodeUnits(ad, ad.add(3), false);
			DataUtilities.createData(currentProgram, ad, t, 4, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			n++;
		}
		println("routed token-list entries typed by form: " + n);
	}

	// ----------------------------------------------------------- kernel

	static final Set<String> ACCESSORS = new HashSet<>(Arrays.asList(
		"gfx_pio_read_32", "gfx_pio_read_64", "gfx_pio_write_32", "gfx_pio_write_64"));

	void applyKernel(EnumDataType hh) throws Exception {
		Map<Long, String> byOff = new HashMap<>();
		for (String nm : hh.getNames()) {
			long v = hh.getValue(nm);
			byOff.merge(v, nm, (a, b) -> a + ";" + b);
		}
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		Listing listing = currentProgram.getListing();
		int n = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (f.isExternal() || f.isThunk()) {
				continue;
			}
			boolean calls = false;
			for (Function c : f.getCalledFunctions(monitor)) {
				calls |= ACCESSORS.contains(c.getName());
			}
			if (!calls) {
				continue;
			}
			DecompileResults r = di.decompileFunction(f, 60, monitor);
			if (!r.decompileCompleted()) {
				println(f.getName() + ": decompile failed");
				continue;
			}
			Iterator<PcodeOpAST> ops = r.getHighFunction().getPcodeOps();
			while (ops.hasNext()) {
				PcodeOpAST op = ops.next();
				if (op.getOpcode() != PcodeOp.CALL || op.getNumInputs() < 2) {
					continue;
				}
				Function callee = getFunctionAt(op.getInput(0).getAddress());
				if (callee == null || !ACCESSORS.contains(callee.getName())) {
					continue;
				}
				Long off = offset(op.getInput(1), 0);
				if (off == null) {
					continue;
				}
				// 0xc00000 is the alias whose bits 3-9 select the same register (HIP.h).
				long reg = off & ~0x400000L;
				String nm = byOff.get(reg);
				if (nm == null || off < 0x800000L || off >= 0xc00400L) {
					continue;
				}
				Address at = op.getSeqnum().getTarget();
				String c = String.format("%s (window 0x%x)", nm, off);
				listing.setComment(at, CommentType.EOL, c);
				println(String.format("hh\t%s\t%s\t0x%x\t%s\t%s", currentProgram.getName(), f.getName(), off,
					callee.getName().contains("read") ? "r" : "w", nm));
				n++;
			}
		}
		di.dispose();
		println("host-interface register accesses named: " + n);
	}

	// The constant part of an address that is a base pointer plus constants.
	// A non-constant term counts as the base. INT_OR with a constant counts
	// as an add: the kernel builds the window offset with lui and ori.
	Long offset(Varnode v, int depth) {
		if (v.isConstant()) {
			return v.getOffset();
		}
		if (depth > 12 || v.getDef() == null) {
			return 0L;
		}
		PcodeOp d = v.getDef();
		switch (d.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return offset(d.getInput(0), depth + 1);
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_OR:
			case PcodeOp.PTRSUB: {
				Long a = offset(d.getInput(0), depth + 1), b = offset(d.getInput(1), depth + 1);
				return a == null || b == null ? null : a + b;
			}
			case PcodeOp.PTRADD: {
				Long a = offset(d.getInput(0), depth + 1);
				if (a == null || !d.getInput(1).isConstant() || !d.getInput(2).isConstant()) {
					return null;
				}
				return a + d.getInput(1).getOffset() * d.getInput(2).getOffset();
			}
			case PcodeOp.LOAD:
			case PcodeOp.MULTIEQUAL:
			case PcodeOp.INDIRECT:
			case PcodeOp.CALL:
				return 0L;
			default:
				return null;
		}
	}
}
