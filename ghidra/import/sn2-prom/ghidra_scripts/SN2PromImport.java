// Lay out an SGI SN2 (Altix, Prism) flash PROM imported as a flat IA-64 image:
// the FIT and its components, the generic PAL_A and its vectors, the
// first-stage SAL entry, the PALE_CHECK and PALE_INIT hand-offs and PAL_B's
// entry vectors, the SAL_B entries, the physical-mode SAL dispatch table and
// SAL_B's global pointer. The br.ia sites in PAL_A are marked as PAL service
// calls (the module README gives the evidence grade). Run as a pre-script on a BinaryLoader
// import with language IA64:LE:64:default; an image loaded at the wrong base
// is moved so it ends at 4 GiB, where the processor finds it.
// Args: [sal-runtime] [gzip-elfs]  sal-runtime also inflates the gzip SAL runtime component and maps its
// IA-64 ELF at RUNTIME_BASE, with its dynamic symbols as functions; gzip-elfs does the same for the
// other gzip ELF components (FIT types 0x13 and 0x1f), each at its own base
// @category IA64
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.*;
import java.util.zip.GZIPInputStream;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;

public class SN2PromImport extends GhidraScript {
	static final long TOP = 0x1_0000_0000L;
	static final long UNCACHED = 0x8000_0000_0000_0000L;
	// FIT types, from the SAL specification's FIT layout and the SN2 kernel's names.
	static final Map<Integer, String> TYPES = Map.of(0x01, "PAL_B", 0x0e, "PAL_A", 0x0f, "PAL_A_generic",
		0x10, "SAL_A", 0x11, "SAL_B", 0x12, "SAL_runtime", 0x1f, "EFI");

	// FIT types that hold IA-64 code; the SAL runtime, EFI and OEM components are packed data.
	static final Set<Integer> CODE = Set.of(0x01, 0x0e, 0x0f, 0x10, 0x11);

	// Where the SAL runtime's ELF is mapped: its link address 0 is this address. SAL_B
	// allocates the buffer it inflates into at run time, so no fixed address is the real one.
	static final long RUNTIME_BASE = 0x1_0000_0000L;
	static final int FIT_SAL_RUNTIME = 0x12;
	// The other gzip ELF components: link address 0 of the type 0x13 file is 0x200000000, of 0x1f 0x300000000.
	static final Map<Integer, Long> ELF_BASE = Map.of(0x13, 2 * RUNTIME_BASE, 0x1f, 3 * RUNTIME_BASE);
	static final long MAX_RUNTIME = 64L << 20;

	Memory mem;
	boolean vectors;

	@Override
	protected void run() throws Exception {
		mem = currentProgram.getMemory();
		MemoryBlock flash = placeImage();
		long base = flash.getStart().getOffset();
		flash.setWrite(false);
		flash.setName("flash");
		// SAL_A reads the FIT through the uncached alias of the flash.
		mem.createByteMappedBlock("flash_uc", addr(UNCACHED | base), flash.getStart(), flash.getSize(),
			false).setWrite(false);

		label(TOP - 0x10, "ia32_reset_vector", "IA-32 reset code (SDM vol 2 11.1.6)");
		qword(TOP - 0x20, "fit_pointer");
		qword(TOP - 0x18, "sale_entry_pointer");
		qword(TOP - 0x38, "alternate_fit_pointer");
		long fit = q(TOP - 0x20) & ~UNCACHED;
		long sale = q(TOP - 0x18) & ~UNCACHED;

		List<long[]> comps = new ArrayList<>();
		DataType entry = fitEntryType();
		if (s8(fit).equals("_FIT_   ")) {
			int count = (int) (q(fit + 8) & 0xffffff);
			for (int i = 0; i < count; i++) {
				long e = fit + 16 * i;
				createData(addr(e), entry);
				if (i == 0) {
					label(e, "FIT", "Firmware Interface Table, " + count + " entries with this header");
					continue;
				}
				int type = (int) (q(e + 8) >> 48) & 0x7f;
				long start = q(e) & ~UNCACHED;
				long size = (q(e + 8) & 0xffffff) * 16;
				int ver = (int) (q(e + 8) >> 32) & 0xffff;
				if (type == 0x7f || size == 0) {
					continue;
				}
				String name = name(type, ver);
				label(e, "FIT_" + i + "_" + name, null);
				label(start, name, String.format("FIT entry %d: type 0x%02x, %#x bytes", i, type, size));
				comps.add(new long[] { start, size, type, ver });
			}
		}
		else {
			printerr("SN2PromImport: no FIT at " + Long.toHexString(fit));
		}

		// The FIT-format entry just below the pointers describes the generic
		// PAL_A, which holds the hardware entries (SDM vol 2 11.1.6).
		long palA = TOP - 0x30;
		createData(addr(palA), entry);
		label(palA, "FIT_PAL_A_generic", null);
		if (((q(palA + 8) >> 48) & 0x7f) == 0x0f) {
			long start = q(palA) & ~UNCACHED;
			comps.add(new long[] { start, TOP - 0x40 - start, 0x0f, (q(palA + 8) >> 32) & 0xffff });
			label(start, "PAL_A_generic", null);
			vectors = true;
		}

		for (long[] c : comps) {
			if (!CODE.contains((int) c[2])) {
				markNotCode(c[0], c[0] + c[1], name((int) c[2], (int) c[3]));
			}
		}
		// One program-tree fragment per component, so an export can take a whole component by name.
		ProgramModule tree = currentProgram.getListing().getDefaultRootModule();
		for (long[] c : comps) {
			if (CODE.contains((int) c[2])) {
				String n = name((int) c[2], (int) c[3]);
				ProgramFragment f = tree.createFragment(n);
				f.move(addr(c[0]), addr(c[0] + c[1] - 1));
			}
		}
		for (long[] c : comps) {
			if (c[2] == 0x0e || c[2] == 0x0f) {
				markPalServiceCalls(c[0], c[0] + c[1]);
			}
		}		for (long[] c : comps) {
			if (CODE.contains((int) c[2])) {
				rfiContinuations(c[0], c[0] + c[1]);
			}
		}
		List<String> opts = Arrays.asList(getScriptArgs());
		for (long[] c : comps) {
			if (c[2] == FIT_SAL_RUNTIME && opts.contains("sal-runtime")) {
				importRuntime(c[0], c[1], name((int) c[2], (int) c[3]), RUNTIME_BASE);
			}
			else if (ELF_BASE.containsKey((int) c[2]) && opts.contains("gzip-elfs")) {
				importRuntime(c[0], c[1], name((int) c[2], (int) c[3]), ELF_BASE.get((int) c[2]));
			}
		}
		if (vectors) {
			// The vector bundles (read from the image, chips snprom pal-msrs.md); 0xffffffb0 is
			// the reset entry. PALE_CHECK and PALE_INIT are inferred from the PAL_B hand-offs.
			// After the br.ia marking, so flow does not follow the IA-32 branch there.
			for (long v = TOP - 0xb0; v <= TOP - 0x50; v += 16) {
				String n = v == TOP - 0x50 ? "PALE_RESET" : v == TOP - 0x60 ? "PALE_INIT"
						: v == TOP - 0x70 ? "PALE_CHECK" : String.format("pal_a_vector_%x", v);
				code(v, n, v >= TOP - 0x70);
			}
		}
		currentProgram.getOptions(Program.DISASSEMBLER_PROPERTIES)
			.setBoolean(Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY, true);
		for (long[] c : comps) {
			long start = c[0];
			int type = (int) c[2];
			String n = name(type, (int) c[3]);
			if (type == 0x0e) {
				// Processor-specific PAL_A is entered at image + 0x300.
				code(start + 0x300, n + "_entry", true);
			}
			else if (type == 0x01) {
				palBEntries(start, n);
				palProcTable(start, start + c[1]);
			}
			else if (type == 0x11) {
				// SAL_B starts with three branch bundles: the reset entry, then
				// the entries SAL_A takes for reasons 2 and 1.
				code(start, "sal_b_reset_entry", true);
				code(start + 0x10, "sal_b_entry_reason2", true);
				code(start + 0x20, "sal_b_entry_reason1", true);
				salDispatch(start, start + c[1]);
			}
		}
		for (long v = TOP - 0x70; v <= TOP - 0x50; v += 16) {
			handler(v);
		}
		if (vectors) {
			// PALE_RESET leaves through an rfi to cr.iip = 0xffff8470 (chips snprom boot-sequence.md),
			// so flow never reaches the FIT walk behind it. Seed it where that image has code.
			long walk = TOP - 0x7b90;
			long t = q(walk) & 31;
			if (t < 0x1e && t != 6 && t != 7 && t != 0xe && t != 0xf && t != 0x14 && t != 0x15 && t != 0x1a
				&& t != 0x1b) {
				code(walk, "pale_reset_fit_walk", true);
			}
		}
		code(sale, "SALE_ENTRY", true);
		currentProgram.getSymbolTable().addExternalEntryPoint(addr(sale));
	}

	// PALE_RESET, PALE_CHECK and PALE_INIT each hold a branch to the code that does the work;
	// make that code a function too.
	void handler(long v) throws Exception {
		Address t = jumpTarget(v);
		if (t != null) {
			String n = v == TOP - 0x50 ? "pale_reset_handler" : v == TOP - 0x60 ? "pale_init_handler"
					: "pale_check_handler";
			code(t.getOffset(), n, true);
		}
	}

	// The target of the unconditional jump in a bundle's slots, or null.
	Address jumpTarget(long bundle) {
		for (int off = 0; off <= 12; off += 6) {
			Instruction in = getInstructionAt(addr(bundle + off));
			if (in != null && in.getFlowType().isUnConditional() && in.getFlowType().isJump()) {
				Address[] f = in.getFlows();
				return f.length == 1 ? f[0] : null;
			}
		}
		return null;
	}

	// Slot units by template (M, I, F, B, or L+X as 'L'); null for a reserved template.
	static final String[] UNITS = new String[32];
	static {
		String[] u = { "MII", "MII", "MII", "MII", "MLX", "MLX", null, null, "MMI", "MMI", "MMI", "MMI", "MFI",
			"MFI", "MMF", "MMF", "MIB", "MIB", "MBB", "MBB", null, null, "BBB", "BBB", "MMB", "MMB", null, null,
			"MFB", "MFB", null, null };
		System.arraycopy(u, 0, UNITS, 0, 32);
	}
	static final long SLOT = (1L << 41) - 1;

	// The 41-bit slots of the bundle at a, or null if its template is reserved.
	long[] slots(long a) throws Exception {
		if (!mem.contains(addr(a)) || !mem.contains(addr(a + 15))) {
			return null;
		}
		long lo = q(a), hi = q(a + 8);
		if (UNITS[(int) (lo & 31)] == null) {
			return null;
		}
		return new long[] { (lo >>> 5) & SLOT, ((lo >>> 46) | (hi << 18)) & SLOT, (hi >>> 23) & SLOT };
	}

	char unit(long a, int i) throws Exception {
		return UNITS[(int) (q(a) & 31)].charAt(i);
	}

	// The PAL's rfi helper (rsm; mov cr.iip=b0; rfi) is entered with b0 = ip + a constant, so the code
	// after the branch to it is reached only through the rfi: make each such continuation a function.
	int rfiContinuations(long start, long end) throws Exception {
		Map<Long, List<long[]>> jumps = new TreeMap<>();
		for (long a = start; a + 16 <= end; a += 16) {
			long[] sl = slots(a);
			if (sl == null) {
				continue;
			}
			for (int i = 0; i < 3; i++) {
				long x = sl[i];
				if (unit(a, i) == 'B' && ((x >>> 37) & 0xf) == 4 && ((x >>> 6) & 7) == 0 && (x & 0x3f) == 0) {
					long d = (((x >>> 36) & 1) << 20) | ((x >>> 13) & 0xfffff);
					jumps.computeIfAbsent(a + (((d << 43) >> 43) << 4), k -> new ArrayList<>())
						.add(new long[] { a, i });
				}
			}
		}
		Set<Long> conts = new TreeSet<>();
		for (Map.Entry<Long, List<long[]>> e : jumps.entrySet()) {
			if (!isRfiHelper(e.getKey())) {
				continue;
			}
			for (long[] site : e.getValue()) {
				Long c = continuation(site[0], (int) site[1]);
				if (c != null && mem.contains(addr(c))) {
					conts.add(c);
				}
			}
		}
		for (long c : conts) {
			code(c, String.format("rfi_continuation_%x", c), true);
		}
		println(String.format("SN2PromImport: %d rfi continuation(s) in %#x..%#x", conts.size(), start, end));
		return conts.size();
	}

	// Straight-line code from t sets cr.iip and then reaches an rfi, with no branch before it.
	boolean isRfiHelper(long t) throws Exception {
		boolean iip = false;
		for (int k = 0; k < 12; k++) {
			long a = t + 16 * k;
			long[] sl = slots(a);
			if (sl == null) {
				return false;
			}
			for (int i = 0; i < 3; i++) {
				long x = sl[i];
				int op = (int) ((x >>> 37) & 0xf);
				int x6 = (int) ((x >>> 27) & 0x3f);
				char u = unit(a, i);
				if (u == 'M' && op == 1 && ((x >>> 33) & 7) == 0 && x6 == 0x2c && ((x >>> 20) & 0x7f) == 19) {
					iip = true;
				}
				else if (u == 'B' && op == 0 && x6 == 8 && ((x >>> 33) & 7) == 0) {
					return iip;
				}
				else if (u == 'B' && (op == 4 || op == 5 || (op == 0 && (x6 == 0x20 || x6 == 0x21)))) {
					return false;
				}
			}
		}
		return false;
	}

	// The address b0 holds at the branch in slot br of the bundle at a, when the few instructions
	// before it make b0 = ip + a constant; null otherwise.
	Long continuation(long a, int br) throws Exception {
		int stage = 0;
		int reg = -1;
		long off = 0;
		for (int k = 0; k < 8; k++) {
			long b = a - 16 * k;
			long[] sl = slots(b);
			if (sl == null) {
				return null;
			}
			for (int i = (k == 0 ? br : 3) - 1; i >= 0; i--) {
				long x = sl[i];
				int op = (int) ((x >>> 37) & 0xf);
				char u = unit(b, i);
				if (stage == 0 && u == 'I' && op == 0 && ((x >>> 33) & 7) == 7 && ((x >>> 6) & 7) == 0
					&& (x & 0x3f) == 0) {
					reg = (int) ((x >>> 13) & 0x7f);
					stage = 1;
				}
				else if (stage == 1 && (u == 'M' || u == 'I') && op == 9 && (x & 0x3f) == 0
					&& ((x >>> 6) & 0x7f) == reg && ((x >>> 20) & 3) == reg) {
					long v = (((x >>> 36) & 1) << 21) | (((x >>> 22) & 0x1f) << 16) | (((x >>> 27) & 0x1ff) << 7)
						| ((x >>> 13) & 0x7f);
					off = (v << 42) >> 42;
					stage = 2;
				}
				else if (stage == 2 && u == 'I' && op == 0 && ((x >>> 33) & 7) == 0 && ((x >>> 27) & 0x3f) == 0x30
					&& ((x >>> 6) & 0x7f) == reg && (x & 0x3f) == 0) {
					return b + off;
				}
			}
		}
		return null;
	}

	// PAL_B opens, 0x10000 into the component, with a run of bundles that each branch to
	// a routine. The PALE_CHECK and PALE_INIT hand-offs enter at +0x10080 and +0x10070 (inferred).
	void palBEntries(long start, String name) throws Exception {
		for (long a = start + 0x10000; a <= start + 0x100a0; a += 16) {
			long off = a - start;
			String n = off == 0x10080 ? name + "_check_entry" : off == 0x10070 ? name + "_init_entry"
					: String.format("%s_entry_%x", name, off);
			code(a, n, true);
			Address t = jumpTarget(a);
			if (t != null) {
				code(t.getOffset(), n + "_body", true);
			}
		}
	}

	// PAL_B links at 0xfff00000 whatever its address in flash; its code holds link addresses.
	static final long PAL_B_LINK = 0xfff00000L;

	// The PAL procedure table, found by shape: 24-byte entries (index, PSR mask, 0) ended by -1,
	// then one 8-byte link address of a handler per entry. The shape is checked against the
	// link address the dispatch code loads for the table, so a mislinked image is skipped.
	void palProcTable(long start, long end) throws Exception {
		long delta = start - PAL_B_LINK;
		long best = -1, bestLen = 0;
		for (long a = start; a + 24 <= end; a += 8) {
			long n = 0;
			while (a + 24 * n + 24 <= end && q(a + 24 * n) >= 0 && q(a + 24 * n) < 0x1000
				&& q(a + 24 * n + 8) != 0 && (q(a + 24 * n + 8) >>> 40) <= 1 && q(a + 24 * n + 16) == 0) {
				n++;
			}
			if (n >= 8 && q(a + 24 * n) == -1L && n > bestLen) {
				best = a;
				bestLen = n;
			}
			a += 24 * Math.max(0, n - 1);
		}
		if (bestLen == 0 || !loadsLinkAddress(start, end, best - delta)) {
			printerr("SN2PromImport: no PAL procedure table in " + Long.toHexString(start));
			return;
		}
		long h = best + 24 * (bestLen + 1);
		while (q(h) == 0) {
			h += 8;
		}
		label(best, "pal_proc_table", bestLen + " (PAL procedure index, PSR mask, 0) entries");
		label(h, "pal_proc_handlers", "link address of the handler for each index");
		for (long i = 0; i < bestLen; i++) {
			long idx = q(best + 24 * i), link = q(h + 8 * i);
			if ((link >>> 32) != 0x80000000L) {
				continue;
			}
			long handler = (link & 0xffffffffL) + delta;
			if (handler < start || handler >= end) {
				continue;
			}
			createData(addr(best + 24 * i), QWordDataType.dataType);
			createData(addr(h + 8 * i), PointerDataType.dataType);
			code(handler, "pal_proc_" + idx, true);
		}
		println(String.format("SN2PromImport: %d PAL procedures from the table at %#x", bestLen, best));
	}

	// True if some movl in [start, end) loads 0x80000000_<link>: the physical alias of a link address.
	boolean loadsLinkAddress(long start, long end, long link) throws Exception {
		long mask = (1L << 41) - 1;
		for (long a = start; a + 16 <= end; a += 16) {
			long lo = q(a), hi = q(a + 8);
			long tmpl = lo & 31;
			if (tmpl != 4 && tmpl != 5) {
				continue;
			}
			long l = ((lo >>> 46) | (hi << 18)) & mask, x = (hi >>> 23) & mask;
			long imm = (l << 22) | (((x >>> 36) & 1) << 63) | (((x >>> 21) & 1) << 21)
				| (((x >>> 22) & 0x1f) << 16) | (((x >>> 27) & 0x1ff) << 7) | ((x >>> 13) & 0x7f);
			if (imm == (0x80000000_00000000L | link)) {
				return true;
			}
		}
		return false;
	}

	// A PAL_A br.ia is a call into the processor's resident service, not a switch to IA-32
	// (inferred, see the IA-64 module README): flag each so the module models it as one.
	void markPalServiceCalls(long start, long end) throws Exception {
		// Units by template: B in slot 1 and 2 of MBB, slot 2 of MIB, MMB and MFB, all of BBB.
		String[] units = new String[32];
		units[0x10] = units[0x11] = "MIB";
		units[0x12] = units[0x13] = "MBB";
		units[0x16] = units[0x17] = "BBB";
		units[0x18] = units[0x19] = "MMB";
		units[0x1c] = units[0x1d] = "MFB";
		long mask = (1L << 41) - 1;
		Register pal = currentProgram.getRegister("pal");
		int found = 0;
		for (long a = start; a + 16 <= end; a += 16) {
			long lo = q(a), hi = q(a + 8);
			String u = units[(int) (lo & 31)];
			if (u == null) {
				continue;
			}
			long[] slot = { (lo >>> 5) & mask, ((lo >>> 46) | (hi << 18)) & mask, (hi >>> 23) & mask };
			for (int i = 0; i < 3; i++) {
				long x = slot[i];
				if (u.charAt(i) == 'B' && ((x >>> 37) & 0xf) == 0 && ((x >>> 27) & 0x3f) == 0x20
					&& ((x >>> 6) & 7) == 1) {
					Address at = addr(a + (i == 0 ? 0 : i == 1 ? 6 : 12));
					currentProgram.getProgramContext().setValue(pal, at, at, BigInteger.ONE);
					found++;
				}
			}
		}
		println(String.format("SN2PromImport: %d br.ia PAL service call(s) in %#x..%#x", found, start, end));
	}

	// The component at start is a gzip stream holding an IA-64 shared object (ET_DYN) with one
	// PT_LOAD at link address 0. Inflate it, map it at base and make its dynamic symbols
	// functions (code) and labels (data). gp is DT_PLTGOT, the value the linker gives such an object.
	// Relocations are not applied: its data holds link-time values.
	void importRuntime(long start, long size, String name, long base) throws Exception {
		byte[] gz = new byte[(int) size];
		mem.getBytes(addr(start), gz);
		byte[] elf = inflate(gz);
		if (elf == null || elf.length < 64 || le(elf, 0, 4) != 0x464c457fL || le(elf, 18, 2) != 50
			|| elf[4] != 2) {
			printerr("SN2PromImport: " + name + " is not a gzip stream holding an IA-64 ELF64 file");
			return;
		}
		long phoff = le(elf, 32, 8);
		int phnum = (int) le(elf, 56, 2);
		long top = 0, dyn = -1;
		for (int i = 0; i < phnum; i++) {
			int ph = (int) phoff + 56 * i;
			long type = le(elf, ph, 4);
			if (type == 1) {
				top = Math.max(top, le(elf, ph + 16, 8) + le(elf, ph + 40, 8));
			}
			else if (type == 2) {
				dyn = le(elf, ph + 16, 8);
			}
		}
		if (top == 0 || top > MAX_RUNTIME || dyn < 0) {
			printerr("SN2PromImport: " + name + " has no loadable segment or dynamic section");
			return;
		}
		byte[] image = new byte[(int) top];
		for (int i = 0; i < phnum; i++) {
			int ph = (int) phoff + 56 * i;
			if (le(elf, ph, 4) == 1) {
				System.arraycopy(elf, (int) le(elf, ph + 8, 8), image, (int) le(elf, ph + 16, 8),
					(int) le(elf, ph + 32, 8));
			}
		}
		name += "_elf";
		MemoryBlock b = mem.createInitializedBlock(name, addr(base), new ByteArrayInputStream(image),
			top, monitor, false);
		b.setRead(true);
		b.setWrite(true);
		b.setExecute(true);
		// The hash table sits at link address 0, so absent is -1, not 0.
		long hash = -1, strtab = -1, symtab = -1, pltgot = 0;
		for (long d = dyn; le(image, (int) d, 8) != 0; d += 16) {
			long v = le(image, (int) d + 8, 8);
			switch ((int) le(image, (int) d, 8)) {
				case 3 -> pltgot = v;
				case 4 -> hash = v;
				case 5 -> strtab = v;
				case 6 -> symtab = v;
				default -> { }
			}
		}
		if (hash < 0 || strtab < 0 || symtab < 0) {
			printerr("SN2PromImport: " + name + " has no dynamic symbol table");
			return;
		}
		if (pltgot != 0) {
			currentProgram.getProgramContext().setValue(currentProgram.getRegister("r1"), b.getStart(),
				b.getEnd(), BigInteger.valueOf(base + pltgot));
		}
		int nsyms = (int) le(image, (int) hash + 4, 4), funcs = 0;
		for (int i = 1; i < nsyms; i++) {
			int sym = (int) symtab + 24 * i;
			int info = image[sym + 4] & 0xf;
			long value = le(image, sym + 8, 8);
			if (le(image, sym + 6, 2) == 0 || value == 0 || (info != 1 && info != 2)) {
				continue;
			}
			int n = (int) strtab + (int) le(image, sym, 4), e = n;
			while (image[e] != 0) {
				e++;
			}
			String sname = new String(image, n, e - n, java.nio.charset.StandardCharsets.ISO_8859_1);
			if (info == 2) {
				code(base + value, sname, true);
				funcs++;
			}
			else {
				label(base + value, sname, null);
			}
		}
		label(base, name + "_base", name + " ELF mapped here, link address 0");
		println(String.format("SN2PromImport: %s mapped at %#x, %d functions, gp %#x", name, base, funcs,
			base + pltgot));
	}

	static byte[] inflate(byte[] gz) {
		if (gz.length < 10 || (gz[0] & 0xff) != 0x1f || (gz[1] & 0xff) != 0x8b) {
			return null;
		}
		try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buf = new byte[1 << 16];
			int n;
			while ((n = in.read(buf)) > 0 && out.size() <= MAX_RUNTIME) {
				out.write(buf, 0, n);
			}
			return out.toByteArray();
		}
		catch (java.io.IOException e) {
			return null;
		}
	}

	static long le(byte[] b, int off, int n) {
		long v = 0;
		for (int i = n - 1; i >= 0; i--) {
			v = v << 8 | (b[off + i] & 0xff);
		}
		return v;
	}

	// Give a data component its own non-executable block and keep disassembly out of such
	// blocks. Otherwise analysis decodes its bytes, and a bogus call inside them splits a
	// real function in two.
	void markNotCode(long start, long end, String name) throws Exception {
		MemoryBlock b = mem.getBlock(addr(start));
		if (b == null || b.getEnd().getOffset() < end - 1) {
			return;
		}
		if (b.getStart().getOffset() < start) {
			mem.split(b, addr(start));
			b = mem.getBlock(addr(start));
		}
		if (b.getEnd().getOffset() >= end) {
			mem.split(b, addr(end));
			mem.getBlock(addr(end)).setName(String.format("flash_%x", end));
			b = mem.getBlock(addr(start));
		}
		b.setExecute(false);
		b.setName(name);
	}

	// Move the loaded bytes so they end at 4 GiB.
	MemoryBlock placeImage() throws Exception {
		MemoryBlock[] blocks = mem.getBlocks();
		if (blocks.length != 1) {
			throw new IllegalStateException("expected one loaded block, found " + blocks.length);
		}
		MemoryBlock b = blocks[0];
		long want = TOP - b.getSize();
		if (b.getStart().getOffset() != want) {
			println(String.format("SN2PromImport: moving the image from %#x to %#x", b.getStart().getOffset(), want));
			mem.moveBlock(b, addr(want), monitor);
			b = mem.getBlock(addr(want));
		}
		return b;
	}

	// The physical-mode SAL table: (function id, descriptor) pairs, each
	// descriptor a code address and the global pointer for it. Found by shape,
	// as the longest run of such pairs inside SAL_B.
	void salDispatch(long lo, long hi) throws Exception {
		long best = -1, bestLen = 0;
		for (long a = lo; a + 16 <= hi; a += 8) {
			long n = 0;
			while (isSalPair(a + 16 * n, lo, hi)) {
				n++;
			}
			if (n > bestLen) {
				best = a;
				bestLen = n;
			}
			a += 16 * Math.max(0, n - 1);
		}
		if (bestLen < 8) {
			printerr("SN2PromImport: no SAL dispatch table in SAL_B");
			return;
		}
		label(best, "sal_dispatch_table", bestLen + " (SAL function id, descriptor) pairs");
		Set<Long> gps = new TreeSet<>();
		for (long i = 0; i < bestLen; i++) {
			long e = best + 16 * i;
			long id = q(e), desc = q(e + 8);
			createData(addr(e), QWordDataType.dataType);
			createData(addr(e + 8), PointerDataType.dataType);
			gps.add(q(desc + 8));
			if (getSymbolAt(addr(desc)) == null) {
				createData(addr(desc), PointerDataType.dataType);
				createData(addr(desc + 8), QWordDataType.dataType);
				label(desc, String.format("sal_desc_%08x", id), null);
			}
			code(q(desc), String.format("sal_%08x", id), true);
		}
		if (gps.size() == 1) {
			long gp = gps.iterator().next();
			currentProgram.getProgramContext().setValue(currentProgram.getRegister("r1"), addr(lo),
				addr(hi - 1), BigInteger.valueOf(gp));
			println(String.format("SN2PromImport: SAL_B gp %#x from %d descriptors", gp, bestLen));
		}
		else {
			printerr("SN2PromImport: descriptors disagree on gp: " + gps);
		}
	}

	boolean isSalPair(long e, long lo, long hi) throws Exception {
		if (e + 16 > hi) {
			return false;
		}
		long id = q(e);
		if (!((id >= 0x01000000L && id <= 0x010000ffL) || (id >= 0x02000000L && id <= 0x020000ffL))) {
			return false;
		}
		long desc = q(e + 8);
		if (!mem.contains(addr(desc)) || !mem.contains(addr(desc + 15))) {
			return false;
		}
		long pc = q(desc);
		return pc >= lo && pc < hi && (pc & 0xf) == 0;
	}

	void code(long a, String name, boolean function) throws Exception {
		Address ad = addr(a);
		label(a, name, null);
		new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
		if (function && getFunctionAt(ad) == null) {
			new CreateFunctionCmd(ad).applyTo(currentProgram, monitor);
		}
	}

	void qword(long a, String name) throws Exception {
		createData(addr(a), QWordDataType.dataType);
		label(a, name, null);
	}

	void label(long a, String name, String comment) throws Exception {
		Address ad = addr(a);
		createLabel(ad, name, true, SourceType.IMPORTED);
		if (comment != null) {
			setPlateComment(ad, comment);
		}
	}

	static String name(int type, int ver) {
		String t = TYPES.getOrDefault(type, String.format("OEM_%02x", type));
		return String.format("%s_%x_%02x", t, ver >> 8, ver & 0xff);
	}

	DataType fitEntryType() {
		StructureDataType s = new StructureDataType("sn2_fit_entry", 0);
		s.add(QWordDataType.dataType, "address", null);
		s.add(new ArrayDataType(ByteDataType.dataType, 3, 1), "size_16", "size in 16-byte units");
		s.add(ByteDataType.dataType, "reserved", null);
		s.add(WordDataType.dataType, "version", "major in the high byte, minor in the low, as BCD");
		s.add(ByteDataType.dataType, "type", "bit 7: checksum valid");
		s.add(ByteDataType.dataType, "checksum", null);
		return currentProgram.getDataTypeManager().addDataType(s, null);
	}

	long q(long a) throws Exception {
		return mem.getLong(addr(a));
	}

	String s8(long a) throws Exception {
		byte[] b = new byte[8];
		mem.getBytes(addr(a), b);
		return new String(b, java.nio.charset.StandardCharsets.ISO_8859_1);
	}

	Address addr(long a) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
	}
}
