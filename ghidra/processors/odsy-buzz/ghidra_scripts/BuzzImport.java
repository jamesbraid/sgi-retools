// Build an ODSY-BUZZ program from a BUZZ microcode image.
//
// Run as an analyzeHeadless -preScript on an image imported raw:
//
//   analyzeHeadless DIR PROJ -import ucode/ODSY/buzz_xform.bin \
//     -loader BinaryLoader -processor ODSY-BUZZ:BE:16:default \
//     -preScript BuzzImport.java
//
// An image is an array of 12-byte records (six big-endian halfwords, bits
// 95:0, ucode/buzz_isa.md); a trailer shorter than a record is ignored. The
// script accepts the three images the workspace holds and tells them apart
// by record count:
//
//   2794  ucode/ODSY/buzz_xform.bin (6.5.30m), numbered as in the documents
//   2266  ucode/buzz_ucode_ip30.bin and _ip35.bin, the kernel's older copy:
//         records from 891 on sit 99 lower and 792 to 890 are missing
//   other diagxform.bin of the field diagnostics, or any other image: end
//         marks only, no program table
//
// Code memory gets record bits 63:0, one 8-byte unit per record, so a code
// address is a record number (Ghidra shows the byte offset, eight times it); bits 93:64 and a few derived bits go into the
// context register at that record (odsy_buzz.slaspec says why). It also
// creates the data spaces with names for what the documents name, labels
// every routine entry and program part, and creates functions: first the
// table programs (whose value-3 marks loop to sequencer 0x2a and exit to
// 0x2c), then every other entry that no function already covers.
//
// @category ODSY

import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class BuzzImport extends GhidraScript {

	static final int XFORM_RECORDS = 2794;
	static final int KERNEL_RECORDS = 2266;
	static final int INSERT_AT = 792, INSERT_LEN = 99;

	// Entries libGLcore's AddProgram stores into the routine list (N32
	// libGLcore.so, ody_program.s), plus 410, the colour-unit data loader
	// (scripts/buzz_ucode_disasm.py, ucode/buzz_isa.md "Programs, entries and
	// dispatch").
	static final int[] LIST = { 12, 26, 40, 51, 77, 82, 87, 92, 97, 102, 107, 108, 119, 123, 127,
		145, 159, 410, 515, 606, 611, 626, 641, 656, 694, 719, 734, 758, 768, 779, 891, 902, 911,
		920, 931, 964, 975, 986, 997, 1013, 1023, 1035, 1045, 1057, 1071, 1094, 1136, 1173, 1198,
		1200, 1211, 1216 };
	// Command-word opcodes of 0x100 and above that are routine entries
	// (ucode/buzz_routines.md, "How a command word reaches a routine").
	static final int[] OPCODE = { 303, 324, 360, 418, 443, 456, 479, 490 };
	// Table programs: sequencer 0x29 (start), 0x2a (loop) and 0x2c (exit) of
	// table records 0 to 13 and 16 to 23 (ucode/buzz_routines.md, "Table
	// records"); 14 and 15 point all three at the null routine.
	static final int[][] PROGRAMS = { { 214, 224, 234 }, { 243, 256, 268 }, { 1313, 1325, 1337 },
		{ 1483, 1496, 1509 }, { 1348, 1364, 1379 }, { 1390, 1406, 1422 }, { 1580, 1597, 1613 },
		{ 1752, 1771, 1789 }, { 1433, 1453, 1472 }, { 1520, 1541, 1561 }, { 1623, 1646, 1668 },
		{ 1689, 1716, 1742 }, { 2300, 2328, 2355 }, { 1798, 1824, 1851 }, { 1862, 1896, 1929 },
		{ 1955, 1990, 2024 }, { 2050, 2085, 2119 }, { 2145, 2180, 2214 }, { 2590, 2626, 2661 },
		{ 2691, 2728, 2764 }, { 2365, 2404, 2442 }, { 2476, 2516, 2555 } };
	static final int IDLE_LO = 1 << 19;

	// Names for inputs (BUZZ.h section 1 slots), as scripts/buzz_ucode_dataflow.py.
	static final String[] SLOT = { "P", "N", "slot2", "T", "slot4", "C", "Mamb", "Mdif", "Mspe",
		"Memi", "Bamb", "Bdif", "Bspe", "Bemi", "load", "grp15" };
	// Parameter words 0x1e0 to 0x1ef (__glOdysseyInitDefaultValues, ody_context.s).
	static final String[] CONST = { "k_1", "k_0_5", "k_m1", "k_0", "k_2sqrt2", "k_3", "k_sqrt2",
		"k_sqrt2_4", "k_m2", "k_msqrt2", "k_msqrt1_2", "k_m0_5", "k_2p17", "k_m32", "k_1_32", "k_0b" };

	int n;
	boolean xform, kernel;

	int map(int rec) {
		if (xform) {
			return rec;
		}
		if (kernel) {
			if (rec >= INSERT_AT && rec < INSERT_AT + INSERT_LEN) {
				return -1;
			}
			int r = rec >= INSERT_AT ? rec - INSERT_LEN : rec;
			return r < n ? r : -1;
		}
		return -1;
	}

	@Override
	protected void run() throws Exception {
		Path src = Paths.get(currentProgram.getExecutablePath());
		byte[] img = Files.readAllBytes(src);
		n = img.length / 12;
		xform = n == XFORM_RECORDS;
		kernel = n == KERNEL_RECORDS;
		println(String.format("%s: %d records, %d trailing bytes; numbering: %s", src.getFileName(), n,
			img.length - 12 * n, xform ? "buzz_xform.bin" : kernel ? "kernel copy" : "own (no program table)"));
		long[] hi = new long[n], lo = new long[n];
		for (int i = 0; i < n; i++) {
			long h = 0, l = 0;
			for (int k = 0; k < 4; k++) {
				h = (h << 8) | (img[12 * i + k] & 0xff);
			}
			for (int k = 4; k < 12; k++) {
				l = (l << 8) | (img[12 * i + k] & 0xff);
			}
			hi[i] = h;
			lo[i] = l;
		}

		Memory mem = currentProgram.getMemory();
		for (MemoryBlock blk : mem.getBlocks()) {
			mem.removeBlock(blk, monitor);
		}
		AddressFactory af = currentProgram.getAddressFactory();
		AddressSpace code = af.getAddressSpace("code");
		byte[] bytes = new byte[8 * n];
		for (int i = 0; i < n; i++) {
			System.arraycopy(img, 12 * i + 4, bytes, 8 * i, 8);
		}
		MemoryBlock cb = mem.createInitializedBlock("code", code.getAddress(0), 8L * n, (byte) 0, monitor, false);
		cb.setPermissions(true, false, true);
		mem.setBytes(code.getAddress(0), bytes);
		cb.setComment("record bits 63:0, one record per address; bits 93:64 are in the context register");
		makeData(mem, af, "vreg", 128, "register file: R0 to R31, four lanes each");
		makeData(mem, af, "pmem", 1024, "parameter memory (0x1a2/0x1bb stores; light records relative to sequencer 0x31)");
		makeData(mem, af, "cmem", 4 * 128, "colour unit memory: entry e at 4e (light i at 3i to 3i+2, model ambient at 24)");
		makeData(mem, af, "inp", 80, "inputs: slot s lane l at 4s+l, operand k of the command word at 64+k");
		makeData(mem, af, "outw", 32, "output packet words");

		SymbolTable st = currentProgram.getSymbolTable();
		AddressSpace vreg = af.getAddressSpace("vreg"), pmem = af.getAddressSpace("pmem"),
				cmem = af.getAddressSpace("cmem"), inp = af.getAddressSpace("inp"),
				outw = af.getAddressSpace("outw");
		String lanes = "xyzw", rgba = "rgba";
		for (int r = 0; r < 32; r++) {
			for (int l = 0; l < 4; l++) {
				st.createLabel(vreg.getAddress(4L * (4 * r + l)), "R" + r + "_" + lanes.charAt(l), SourceType.IMPORTED);
			}
		}
		for (int s = 0; s < 16; s++) {
			for (int l = 0; l < 4; l++) {
				st.createLabel(inp.getAddress(4L * (4 * s + l)), SLOT[s] + "_" + lanes.charAt(l), SourceType.IMPORTED);
			}
			st.createLabel(inp.getAddress(4L * (64 + s)), "op" + s, SourceType.IMPORTED);
		}
		for (int k = 0; k < 1024; k++) {
			boolean c = k >= 0x1e0 && k < 0x1f0;
			st.createLabel(pmem.getAddress(4L * k), c ? CONST[k - 0x1e0] : String.format("pm_%03x", k),
				SourceType.IMPORTED);
		}
		for (int e = 0; e < 128; e++) {
			for (int l = 0; l < 4; l++) {
				st.createLabel(cmem.getAddress(4L * (4 * e + l)), "col" + e + "_" + rgba.charAt(l), SourceType.IMPORTED);
			}
		}
		for (int w = 0; w < 32; w++) {
			st.createLabel(outw.getAddress(4L * w), "word" + w, SourceType.IMPORTED);
		}

		// Every word of the data spaces is a 32-bit float.
		for (String sp : new String[] { "vreg", "pmem", "cmem", "inp", "outw" }) {
			MemoryBlock b = mem.getBlock(af.getAddressSpace(sp).getAddress(0));
			for (Address a = b.getStart(); a.compareTo(b.getEnd()) < 0; a = a.add(4)) {
				DataUtilities.createData(currentProgram, a, FloatDataType.dataType, 4,
					DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
		}

		// End marks, the marks that fall inside an earlier mark's delay slots,
		// and the value-3 marks of known programs.
		int[] sq = new int[n];
		boolean[] nested = new boolean[n];
		int lastMark = -10;
		for (int i = 0; i < n; i++) {
			sq[i] = (int) (lo[i] & 3);
			if (sq[i] != 0) {
				if (i - lastMark <= 4) {
					nested[i] = true;
				}
				else {
					lastMark = i;
				}
			}
		}
		int[] loop = new int[n], exit = new int[n];
		List<int[]> progs = new ArrayList<>();
		for (int[] p : PROGRAMS) {
			int a = map(p[0]), b = map(p[1]), c = map(p[2]);
			if (a < 0 || b < 0 || c < 0) {
				continue;
			}
			progs.add(new int[] { a, b, c });
			// A patch record: an end mark whose delay slots hold the loop or
			// exit record. It runs only when copied over the program's value-3
			// mark, so its own delay slots are not flow; show it without flow.
			for (int m = Math.max(0, b - 4); m < b; m++) {
				if (sq[m] != 0 && m >= a) {
					nested[m] = true;
				}
			}
			for (int m = a; m < c; m++) {
				if (sq[m] == 3 && !nested[m]) {
					loop[m] = b;
					exit[m] = c;
				}
			}
		}

		ProgramContext pc = currentProgram.getProgramContext();
		Register ctx = pc.getBaseContextRegister();
		String[] names = { "ca", "cr1", "cr2", "cr3", "cb", "cln", "crb", "cbx", "xa0", "xa1", "xr1h",
			"xr1l", "xm0", "xm1", "xm2", "xm3", "xr3h", "xln2", "xlnl", "xbx2", "xbxl", "fvalid", "fidle",
			"fdly", "fnest", "fprog", "floop", "fexit" };
		Map<String, Register> reg = new HashMap<>();
		for (String s : names) {
			Register r = currentProgram.getRegister(s);
			if (r == null) {
				throw new Exception("context field " + s + " missing from the language");
			}
			reg.put(s, r);
		}
		monitor.initialize(n);
		monitor.setMessage("ODSY-BUZZ context");
		for (int i = 0; i < n; i++) {
			monitor.checkCancelled();
			monitor.setProgress(i);
			long h = hi[i];
			long a = (h >> 28) & 3, r1 = (h >> 23) & 31, r2 = (h >> 18) & 31, r3 = (h >> 13) & 31;
			long b = (h >> 11) & 3, ln = (h >> 8) & 7, rb = (h >> 3) & 31, bx = h & 7;
			long[] v = { a, r1, r2, r3, b, ln, rb, bx, a & 1, a >> 1, r1 >> 4, r1 & 3, r1 & 1, (r1 >> 1) & 1,
				(r1 >> 2) & 1, (r1 >> 3) & 1, r3 >> 4, ln >> 2, ln & 3, bx >> 2, bx & 3, 1,
				(h == 0 && lo[i] == IDLE_LO) ? 1 : 0, Math.min(4, n - 1 - i), nested[i] ? 1 : 0,
				loop[i] != 0 ? 1 : 0, loop[i], exit[i] };
			RegisterValue rv = new RegisterValue(ctx);
			for (int k = 0; k < names.length; k++) {
				rv = rv.assign(reg.get(names[k]), BigInteger.valueOf(v[k]));
			}
			Address ad = code.getAddress(8L * i);
			pc.setRegisterValue(ad, ad.add(7), rv);
		}

		// Entries: record 0, the record five after every end mark, the list and
		// opcode entries, and the three parts of each table program.
		TreeMap<Integer, String> entries = new TreeMap<>();
		entries.put(0, "entry_0");
		for (int i = 0; i < n; i++) {
			// A known program's value-3 mark continues at its loop or exit
			// record, which the program labels name instead.
			if (sq[i] != 0 && i + 5 < n && loop[i] == 0) {
				entries.putIfAbsent(i + 5, "entry_" + (i + 5));
			}
		}
		for (int e : LIST) {
			int m = map(e);
			if (m >= 0) {
				entries.putIfAbsent(m, "entry_" + m);
			}
		}
		for (int e : OPCODE) {
			int m = map(e);
			if (m >= 0) {
				entries.putIfAbsent(m, "entry_" + m);
			}
		}
		for (int k = 0; k < progs.size(); k++) {
			int[] p = progs.get(k);
			st.createLabel(code.getAddress(8L * p[0]), "prog_" + p[0] + "_start", SourceType.IMPORTED);
			st.createLabel(code.getAddress(8L * p[1]), "prog_" + p[0] + "_loop", SourceType.IMPORTED);
			st.createLabel(code.getAddress(8L * p[2]), "prog_" + p[0] + "_exit", SourceType.IMPORTED);
		}
		for (Map.Entry<Integer, String> e : entries.entrySet()) {
			st.createLabel(code.getAddress(8L * e.getKey()), e.getValue(), SourceType.IMPORTED);
		}

		// Decode every record first, without following flow, so each mark finds
		// its delay slots decoded.
		AddressSet all = new AddressSet(code.getAddress(0), code.getAddress(8L * n - 1));
		new DisassembleCommand(all, all, false).applyTo(currentProgram, monitor);

		int nf = 0, inside = 0;
		for (int[] p : progs) {
			Address ad = code.getAddress(8L * p[0]);
			st.addExternalEntryPoint(ad);
			if (getFunctionAt(ad) == null && createFunction(ad, "prog_" + p[0]) != null) {
				nf++;
			}
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		for (Map.Entry<Integer, String> e : entries.entrySet()) {
			Address ad = code.getAddress(8L * e.getKey());
			st.addExternalEntryPoint(ad);
			if (fm.getFunctionContaining(ad) != null) {
				inside++;
				continue;
			}
			if (createFunction(ad, "routine_" + e.getKey()) != null) {
				nf++;
			}
		}
		println(String.format("%d entries, %d programs; %d functions created, %d entries inside a program's flow",
			entries.size(), progs.size(), nf, inside));
	}

	private void makeData(Memory mem, AddressFactory af, String sp, long words, String comment)
			throws Exception {
		AddressSpace s = af.getAddressSpace(sp);
		MemoryBlock b = mem.createUninitializedBlock(sp, s.getAddress(0), 4 * words, false);
		b.setPermissions(true, true, false);
		b.setComment(comment);
	}
}
