// Build a KONA-GED program from the distributor program file ged1b.u.
//
// Run as an analyzeHeadless -preScript on a file imported raw:
//
//   analyzeHeadless DIR PROJ -import ucode/KONA/ged1b.u -loader BinaryLoader \
//     -processor KONA-GED:BE:32:default -preScript KonaGEDImport.java [REPO]
//
// REPO is the repository root (default: the working directory); the script
// reads ucode/ged_relocs.tsv from it for the relocated handler slots.
//
// ged1b.u (IRIX 6.5.30m) has the container of the other KONA microcode
// files: eleven header words, then segments of {byte address, byte length,
// data}. Segment one is the program (931 words at 0), segment two the table
// block at byte 0x1000: table A (16 words) and table B (512 words), the
// "pcl table" the ARM loads through distributor registers 0x210-0x213
// (ucode/ged.md, "How an entry is chosen"). The script maps both at their
// byte addresses, so program word i is address 4 x i, as scripts/ged_disasm.py
// numbers them.
//
// Also: the line table as file:line end-of-line comments, the relocated
// engine handler slots as comments, both tables typed as data with a
// reference from every table B entry to its program word, and a labelled
// entry point at every word a table B entry starts.
//
// @category KONA

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class KonaGEDImport extends GhidraScript {

	static int be32(byte[] b, int o) {
		return ((b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
	}

	static int be16(byte[] b, int o) {
		return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Path repo = Paths.get(args.length > 0 ? args[0] : System.getProperty("user.dir")).toAbsolutePath();
		Path src = Paths.get(currentProgram.getExecutablePath());
		byte[] b = Files.readAllBytes(src);
		if ((be32(b, 0) >>> 16) != 0x4591) {
			throw new IOException(String.format("%s: magic 0x%08x is not a distributor program", src, be32(b, 0)));
		}
		int[] h = new int[11];
		for (int i = 0; i < 11; i++) {
			h[i] = be32(b, 4 * i);
		}
		AddressSpace ram = currentProgram.getAddressFactory().getDefaultAddressSpace();
		Memory mem = currentProgram.getMemory();
		for (MemoryBlock blk : mem.getBlocks()) {
			mem.removeBlock(blk, monitor);
		}
		int progWords = 0;
		int o = h[3], end = h[3] + h[4], seg = 0;
		while (o < end) {
			int ba = be32(b, o), bl = be32(b, o + 4);
			o += 8;
			if (bl == 0) {
				break;
			}
			String name = seg == 0 ? "program" : "tables";
			MemoryBlock blk = mem.createInitializedBlock(name, ram.getAddress(ba), bl, (byte) 0, monitor, false);
			mem.setBytes(ram.getAddress(ba), Arrays.copyOfRange(b, o, o + bl));
			if (seg == 0) {
				blk.setPermissions(true, false, true);
				blk.setComment("distributor program, one 32-bit word per instruction");
				progWords = bl / 4;
			}
			else {
				blk.setPermissions(true, false, false);
				blk.setComment("table A (16 words) and table B (512 words)");
			}
			o += bl;
			seg++;
		}
		println(String.format("%s: %d program words, %d segments", src.getFileName(), progWords, seg));

		Listing listing = currentProgram.getListing();
		SymbolTable st = currentProgram.getSymbolTable();

		// Line table: {word, line, file index} records; file names as NUL-
		// terminated strings (scripts/ged_disasm.py).
		List<String> files = new ArrayList<>();
		int fo = h[9], fe = h[9] + h[10];
		while (fo < fe) {
			int e = fo;
			while (e < fe && b[e] != 0) {
				e++;
			}
			String f = new String(b, fo, e - fo, StandardCharsets.ISO_8859_1);
			files.add(f.substring(f.lastIndexOf('/') + 1));
			fo = e + 1;
		}
		Map<Integer, String> line = new TreeMap<>();
		for (int i = 0; i + 8 <= h[6]; i += 8) {
			int q = h[5] + i;
			int w = be32(b, q), ln = be16(b, q + 4), fi = be16(b, q + 6);
			if (fi < files.size()) {
				line.putIfAbsent(w, files.get(fi) + ":" + ln);
			}
		}

		// Relocated slots: arm1.u init_ged_ucode replaces the low 16 bits of
		// these loads with a geometry-engine handler address (ucode/arm1.md).
		Map<Integer, String> reloc = new HashMap<>();
		Path rp = repo.resolve("ucode/ged_relocs.tsv");
		if (Files.exists(rp)) {
			for (String l : Files.readAllLines(rp)) {
				String[] r = l.split("\t");
				if (r.length > 5 && r[0].startsWith("0x")) {
					reloc.put(Integer.decode(r[0]), "slot " + r[3] + ": " + r[5]);
				}
			}
		}
		for (int i = 0; i < progWords; i++) {
			List<String> c = new ArrayList<>();
			if (line.containsKey(i)) {
				c.add(line.get(i));
			}
			if (reloc.containsKey(i)) {
				c.add(reloc.get(i));
			}
			if (!c.isEmpty()) {
				listing.setComment(ram.getAddress(4L * i), CommentType.EOL, String.join("; ", c));
			}
		}

		// A transfer followed by a transfer gets no delay slot (context
		// nodly): Ghidra cannot decode a transfer inside a delay slot.
		ghidra.program.model.lang.Register nodly = currentProgram.getRegister("nodly");
		int nd = 0;
		for (int i = 0; i + 1 < progWords; i++) {
			int w = mem.getInt(ram.getAddress(4L * i)), n = mem.getInt(ram.getAddress(4L * i + 4));
			if ((w >>> 30) == 1 && (n >>> 30) == 1) {
				currentProgram.getProgramContext().setValue(nodly, ram.getAddress(4L * i), ram.getAddress(4L * i + 3),
					java.math.BigInteger.ONE);
				nd++;
			}
		}
		println("transfers followed by a transfer, decoded without a delay slot: " + nd);

		// Decode every word on its own, so each transfer finds its delay
		// slot decoded and no word depends on flow reaching it.
		AddressSet all = new AddressSet(ram.getAddress(0), ram.getAddress(4L * progWords - 1));
		new DisassembleCommand(all, all, false).applyTo(currentProgram, monitor);

		// Tables.
		if (seg < 2) {
			return;
		}
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		CategoryPath cat = new CategoryPath("/KONA/ged");
		DataType aT = dtm.addDataType(new TypedefDataType(cat, "ged_table_a",
			UnsignedIntegerDataType.dataType, dtm), DataTypeConflictHandler.REPLACE_HANDLER);
		DataType bT = dtm.addDataType(new TypedefDataType(cat, "ged_table_b",
			UnsignedIntegerDataType.dataType, dtm), DataTypeConflictHandler.REPLACE_HANDLER);
		Address ta = ram.getAddress(0x1000), tb = ram.getAddress(0x1040);
		DataUtilities.createData(currentProgram, ta, new ArrayDataType(aT, 16, 4, dtm), 64,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		DataUtilities.createData(currentProgram, tb, new ArrayDataType(bT, 512, 4, dtm), 2048,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		st.createLabel(ta, "table_A", SourceType.IMPORTED);
		st.createLabel(tb, "table_B", SourceType.IMPORTED);
		listing.setComment(ta, CommentType.PLATE,
			"Table A: one word per primitive class (r48); 8 x A[class] is the class's first table B index (ucode/ged.md)");
		listing.setComment(tb, CommentType.PLATE,
			"Table B: 512 program word addresses; index 8 x A[r48] + 4 x state + j (ucode/ged.md, inferred rule)");
		for (int c = 0; c < 16; c++) {
			int v = mem.getInt(ta.add(4L * c));
			if (v != 0 || c == 0) {
				listing.setComment(ta.add(4L * c), CommentType.EOL,
					String.format("class %d: table B from 0x%03x", c, 8 * v));
			}
		}
		ReferenceManager rm = currentProgram.getReferenceManager();
		TreeMap<Integer, List<Integer>> starts = new TreeMap<>();
		for (int n = 0; n < 512; n++) {
			int w = mem.getInt(tb.add(4L * n));
			if (w < 0 || w >= progWords) {
				println(String.format("table B[0x%03x] = 0x%x is outside the program", n, w));
				continue;
			}
			rm.addMemoryReference(tb.add(4L * n), ram.getAddress(4L * w), RefType.DATA, SourceType.IMPORTED, 0);
			starts.computeIfAbsent(w, x -> new ArrayList<>()).add(n);
		}
		for (Map.Entry<Integer, List<Integer>> e : starts.entrySet()) {
			Address ad = ram.getAddress(4L * e.getKey());
			st.createLabel(ad, String.format("B_%03x", e.getValue().get(0)), SourceType.IMPORTED);
			st.addExternalEntryPoint(ad);
			listing.setComment(ad, CommentType.PRE, "table B entries " + ranges(e.getValue()));
			if (getFunctionAt(ad) == null) {
				createFunction(ad, null);
			}
		}
		println(String.format("table B: %d distinct entry words", starts.size()));
	}

	static String ranges(List<Integer> ns) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < ns.size();) {
			int j = i;
			while (j + 1 < ns.size() && ns.get(j + 1) == ns.get(j) + 1) {
				j++;
			}
			if (sb.length() > 0) {
				sb.append(',');
			}
			sb.append(i == j ? String.format("%03x", ns.get(i)) : String.format("%03x-%03x", ns.get(i), ns.get(j)));
			i = j + 1;
		}
		return sb.toString();
	}
}
