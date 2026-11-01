// Build a GE11 program from an IMPACT geometry-engine microcode file.
//
// Run as an analyzeHeadless -preScript on a file imported raw:
//
//   analyzeHeadless DIR PROJ -import ucode/mgras_ge.u -loader BinaryLoader \
//     -processor GE11:BE:32:default -preScript GE11Import.java [ARGS]
//
// Accepts mgras_ge*.u (magic 0x45900003, 32-byte decoded records, with its
// line and file tables), mgras_ge*.hex and the 6.5.7 diagnostic's
// mgras_ge.hex (address and 18 hex digits a line), and ge11*.bin (12-byte
// words: bits 31-0, 63-32, then 71-64 in the low byte). The decode needs the
// 72-bit word W and its decoded record. A .u gives the records and its
// sibling .hex the words; a .hex beside its .u is paired with it; any other
// file gets its records from data/ge11_decode.tsv (tools/ge11_decode.py).
// The fill word febaadcafebaadcafe, which ge11*.bin puts at every address
// the program leaves unused, is left undefined. Code memory
// gets W[63:0], one 8-byte unit per word; the record groups and W[71:64] go
// into the context register at that word (see ge11.slaspec). Padding words
// (W = 0 with record bits 62-8 clear) get the canonical no-op record, since
// W = 0 is a no-op word.
//
// Also: source file:line EOL comments from the .u line table, a label and an
// entry point at the first word of each source file, an entry at word 0 and
// at every handler of the sibling dispatch table (mgras_geif*.u: 512
// big-endian words, word k the start of command k), CHIP_REV at 0xfffe0018,
// and uninitialised WRAM, CRAM and ERAM blocks.
//
// Arguments (optional): a label file, either "NAME ADDRESS" lines or the
// diagnostic's ge11symtab.h ("#define NAME (0xADDRESS)"); every label in it
// becomes an entry point.
//
// @category GE11

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class GE11Import extends GhidraScript {

	// Canonical no-op record (record of every form-0 word that is not padding).
	static final BigInteger NOP = new BigInteger(
		"894000180007fe007feb77febd0006fe4007ff00005c3e29c00", 16);

	// ge11*.bin fills the addresses its program does not use with this word.
	static final BigInteger FILL = new BigInteger("febaadcafebaadcafe", 16);

	static class Prog {
		TreeMap<Integer, BigInteger> w = new TreeMap<>();   // address -> W (72 bits)
		TreeMap<Integer, BigInteger> r = new TreeMap<>();   // address -> record (256 bits)
		TreeMap<Integer, String> line = new TreeMap<>();    // address -> file:line
	}

	static int be32(byte[] b, int o) {
		return ((b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
	}

	static int be16(byte[] b, int o) {
		return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff);
	}

	static void readHex(Path p, Prog pr) throws IOException {
		for (String l : Files.readAllLines(p)) {
			String[] f = l.trim().split("\\s+");
			if (f.length != 2) {
				continue;
			}
			pr.w.put(Integer.parseInt(f[0], 16), new BigInteger(f[1], 16));
		}
	}

	// Container shared by ge.u and ge11.u: eleven words, then (offset, length)
	// pairs; code segments are (byte address, byte length) plus records.
	static void readU(Path p, Prog pr) throws IOException {
		byte[] b = Files.readAllBytes(p);
		int magic = be32(b, 0);
		int[] h = new int[11];
		for (int i = 0; i < 11; i++) {
			h[i] = be32(b, 4 * i);
		}
		int rec = magic == 0x45900003 ? 32 : magic == 0x45930003 ? 12 : 0;
		if (rec == 0) {
			throw new IOException(String.format("%s: magic 0x%08x is not a geometry-engine program", p, magic));
		}
		int o = h[3], end = h[3] + h[4];
		while (o < end) {
			int ba = be32(b, o), bl = be32(b, o + 4);
			o += 8;
			for (int i = 0; i < bl / rec; i++) {
				int a = ba / rec + i, q = o + rec * i;
				if (rec == 32) {
					pr.r.put(a, new BigInteger(1, Arrays.copyOfRange(b, q, q + 32)));
				}
				else {
					// W bits 0-31, 32-63, then 64-71, each a big-endian word (ge.md).
					BigInteger w = BigInteger.valueOf(be32(b, q) & 0xffffffffL)
						.or(BigInteger.valueOf(be32(b, q + 4) & 0xffffffffL).shiftLeft(32))
						.or(BigInteger.valueOf(be32(b, q + 8) & 0xffL).shiftLeft(64));
					pr.w.put(a, w);
				}
			}
			o += bl;
		}
		if (rec == 32 && h[6] > 0) {
			int fo = h[7], fl = h[8], no = h[9];
			String[] files = new String[fl / 2];
			for (int i = 0; i < files.length; i++) {
				int x = no + be16(b, fo + 2 * i), e = x;
				while (b[e] != 0) {
					e++;
				}
				String n = new String(b, x, e - x, "ISO-8859-1");
				files[i] = n.substring(n.lastIndexOf('/') + 1);
			}
			for (int i = 0; i < h[6] / 8; i++) {
				int q = h[5] + 8 * i;
				int ia = be32(b, q), ln = be16(b, q + 4), fi = be16(b, q + 6);
				pr.line.putIfAbsent(ia, files[fi] + ":" + ln);
			}
		}
	}

	// 12-byte words: bits 31-0, 63-32, then 71-64 in the low byte.
	static void readBin(Path p, Prog pr) throws IOException {
		byte[] b = Files.readAllBytes(p);
		for (int i = 0; i + 12 <= b.length; i += 12) {
			BigInteger w = BigInteger.valueOf(be32(b, i) & 0xffffffffL)
				.or(BigInteger.valueOf(be32(b, i + 4) & 0xffffffffL).shiftLeft(32))
				.or(BigInteger.valueOf(be32(b, i + 8) & 0xffL).shiftLeft(64));
			pr.w.put(i / 12, w);
		}
	}

	// data/ge11_decode.tsv: per (form, record bit) the leaves of a decision
	// tree over W bits; exactly one leaf of each matches a word.
	static class Leaf {
		int[] bit, val;
		int src; // -1 constant 0, -2 constant 1, else W bit; neg set: inverted
		boolean inv;
	}

	List<Leaf>[][] table;

	@SuppressWarnings("unchecked")
	void readTable(Path p) throws IOException {
		table = new List[16][256];
		for (String l : Files.readAllLines(p)) {
			if (l.startsWith("#") || l.startsWith("form")) {
				continue;
			}
			String[] t = l.split("\t");
			int f = Integer.parseInt(t[0]), k = Integer.parseInt(t[1]);
			Leaf lf = new Leaf();
			String[] c = t[2].equals("-") ? new String[0] : t[2].split(",");
			lf.bit = new int[c.length];
			lf.val = new int[c.length];
			for (int i = 0; i < c.length; i++) {
				String[] bv = c[i].split("=");
				lf.bit[i] = Integer.parseInt(bv[0]);
				lf.val[i] = Integer.parseInt(bv[1]);
			}
			String v = t[3];
			if (v.equals("0")) {
				lf.src = -1;
			}
			else if (v.equals("1")) {
				lf.src = -2;
			}
			else {
				lf.inv = v.startsWith("~");
				lf.src = Integer.parseInt(v.substring(lf.inv ? 2 : 1));
			}
			if (table[f][k] == null) {
				table[f][k] = new ArrayList<>();
			}
			table[f][k].add(lf);
		}
	}

	BigInteger decode(BigInteger w) {
		int f = (int) field(w, 70, 67);
		if (table[f][0] == null) {
			return null;
		}
		BigInteger r = BigInteger.ZERO;
		for (int k = 0; k < 256; k++) {
			for (Leaf lf : table[f][k]) {
				boolean ok = true;
				for (int i = 0; i < lf.bit.length && ok; i++) {
					ok = (w.testBit(lf.bit[i]) ? 1 : 0) == lf.val[i];
				}
				if (!ok) {
					continue;
				}
				boolean v = lf.src == -2 || (lf.src >= 0 && (w.testBit(lf.src) != lf.inv));
				if (v) {
					r = r.setBit(k);
				}
				break;
			}
		}
		return r;
	}

	static Path sibling(Path p, String name) {
		Path s = p.resolveSibling(name);
		return Files.exists(s) ? s : null;
	}

	static long field(BigInteger r, int hi, int lo) {
		return r.shiftRight(lo).and(BigInteger.ONE.shiftLeft(hi - lo + 1).subtract(BigInteger.ONE)).longValue();
	}

	static boolean isPadding(BigInteger w, BigInteger r) {
		return w.signum() == 0 && field(r, 62, 8) == 0;
	}

	@Override
	protected void run() throws Exception {
		Path src = Paths.get(currentProgram.getExecutablePath());
		String name = src.getFileName().toString();
		Prog pr = new Prog();
		byte[] head = Arrays.copyOf(Files.readAllBytes(src), 4);
		int magic = be32(head, 0);
		String base = name.contains(".") ? name.substring(0, name.lastIndexOf('.')) : name;
		Path recFile = null;
		int derived = 0, undecodable = 0, fill = 0;
		if (magic == 0x45900003) {
			recFile = src;
			readU(src, pr);
			Path h = sibling(src, base + ".hex");
			if (h != null) {
				readHex(h, pr);
			}
		}
		else {
			if (name.endsWith(".bin")) {
				readBin(src, pr);
			}
			else {
				readHex(src, pr);
				recFile = sibling(src, base + ".u");
				if (recFile != null) {
					readU(recFile, pr);
				}
			}
			if (recFile == null) {
				Path t = Paths.get(getSourceFile().getParentFile().getParentFile().getAbsolutePath(),
					"data", "ge11_decode.tsv");
				readTable(t);
				for (Map.Entry<Integer, BigInteger> e : pr.w.entrySet()) {
					if (e.getValue().equals(FILL)) {
						fill++;
						continue;
					}
					BigInteger r = decode(e.getValue());
					if (r == null) {
						undecodable++;
						continue;
					}
					pr.r.put(e.getKey(), r);
					derived++;
				}
			}
		}
		println(String.format("%s: %d records, %d words; records %s", name, pr.r.size(), pr.w.size(),
			recFile != null ? "from " + recFile.getFileName()
					: String.format("decoded by data/ge11_decode.tsv (%d words, %d in a form with no table, "
						+ "%d fill words left undefined)", derived, undecodable, fill)));
		for (Map.Entry<Integer, BigInteger> e : pr.w.entrySet()) {
			if (!pr.r.containsKey(e.getKey()) && recFile != null) {
				throw new IOException(String.format("word 0x%04x has no record", e.getKey()));
			}
		}

		Memory mem = currentProgram.getMemory();
		for (MemoryBlock blk : mem.getBlocks()) {
			mem.removeBlock(blk, monitor);
		}
		AddressFactory af = currentProgram.getAddressFactory();
		AddressSpace code = af.getAddressSpace("code");
		int last = Math.max(pr.r.lastKey(), pr.w.isEmpty() ? 0 : pr.w.lastKey());
		int n = last + 1;
		byte[] img = new byte[8 * n];
		for (Map.Entry<Integer, BigInteger> e : pr.w.entrySet()) {
			long lo = e.getValue().longValue();
			for (int i = 0; i < 8; i++) {
				img[8 * e.getKey() + i] = (byte) (lo >>> (56 - 8 * i));
			}
		}
		MemoryBlock cb = mem.createInitializedBlock("code", code.getAddress(0), 8L * n, (byte) 0, monitor, false);
		cb.setPermissions(true, false, true);
		mem.setBytes(code.getAddress(0), img);
		makeData(mem, af, "wram", 0x800, "WRAM: 2K words, command FIFO and scratch (GE11 test description)");
		makeData(mem, af, "cram", 0x200, "CRAM: 512 words shared by the cores (GE11 test description)");
		makeData(mem, af, "eram", 0x10000, "ERAM: external SRAM (64K words addressed by the kernel, GE11.h)");

		// Context: every record group, by field name, at its word.
		ProgramContext pc = currentProgram.getProgramContext();
		Register ctx = pc.getBaseContextRegister();
		String[][] f = {
			{ "fimm", "255", "224" }, { "fw71", "223", "223" }, { "f222", "222", "222" },
			{ "f221", "221", "221" }, { "f220", "220", "220" }, { "f219", "219", "218" },
			{ "f217", "217", "216" }, { "f215", "215", "214" }, { "f213", "213", "212" },
			{ "f211", "211", "210" }, { "fcc", "209", "199" }, { "f198", "198", "192" },
			{ "fA", "191", "187" }, { "fB", "186", "182" }, { "fC", "181", "177" },
			{ "f176", "176", "175" }, { "fD", "174", "169" }, { "fE", "168", "163" },
			{ "f162", "162", "160" }, { "fF", "159", "154" }, { "fG", "153", "149" },
			{ "f148h", "148", "144" }, { "f148l", "143", "139" }, { "fP", "138", "134" },
			{ "fQ", "133", "129" }, { "f128", "128", "122" }, { "fMk", "121", "118" },
			{ "fMu", "117", "111" }, { "f110", "110", "100" }, { "f99h", "99", "99" },
			{ "f99l", "98", "96" }, { "f95", "95", "89" }, { "fsind", "88", "88" },
			{ "fsrel", "87", "87" }, { "fsop", "86", "84" }, { "fsmid", "83", "77" },
			{ "fsgrp", "76", "72" }, { "f71", "71", "63" }, { "f62h", "62", "58" },
			{ "f62l", "57", "26" }, { "f25", "25", "0" } };
		Register[] regs = new Register[f.length];
		for (int i = 0; i < f.length; i++) {
			regs[i] = currentProgram.getRegister(f[i][0]);
			if (regs[i] == null) {
				throw new IOException("context field " + f[i][0] + " missing from the language");
			}
		}
		// Delay slots Ghidra can model: the words before the next transfer, at
		// most four (eight after a return). See kona_ge.slaspec.
		Map<Integer, Integer> dly = new HashMap<>();
		for (Map.Entry<Integer, BigInteger> e : pr.r.entrySet()) {
			BigInteger r = e.getValue();
			long op = field(r, 86, 84);
			if (op == 6 || isPadding(pr.w.getOrDefault(e.getKey(), BigInteger.ZERO), r)) {
				continue;
			}
			boolean ret = (op == 4 || op == 5) && field(r, 88, 88) == 1 && field(r, 76, 72) != 31;
			int k = 0;
			for (int j = 1; j <= (ret ? 8 : 4); j++) {
				BigInteger q = pr.r.get(e.getKey() + j);
				if (q == null) {
					break;
				}
				if (!isPadding(pr.w.getOrDefault(e.getKey() + j, BigInteger.ZERO), q) && field(q, 86, 84) != 6) {
					break;
				}
				k++;
			}
			dly.put(e.getKey(), k);
		}
		Register fdly = currentProgram.getRegister("fdly");
		Register valid = currentProgram.getRegister("fvalid");
		Register wtop = currentProgram.getRegister("fwtop");
		Register form = currentProgram.getRegister("fform");
		int pad = 0;
		monitor.initialize(n);
		monitor.setMessage("GE11 context");
		for (int a = 0; a < n; a++) {
			monitor.checkCancelled();
			monitor.setProgress(a);
			BigInteger r = pr.r.get(a);
			if (r == null) {
				// No record (fill): an explicit fvalid of 0 matches no
				// constructor, so the word stays undefined.
				Address ad = code.getAddress(8L * a);
				pc.setRegisterValue(ad, ad.add(7), new RegisterValue(ctx).assign(valid, BigInteger.ZERO));
				continue;
			}
			BigInteger w = pr.w.getOrDefault(a, BigInteger.ZERO);
			if (isPadding(w, r)) {
				r = NOP;
				pad++;
			}
			RegisterValue rv = new RegisterValue(ctx);
			for (int i = 0; i < f.length; i++) {
				long v = field(r, Integer.parseInt(f[i][1]), Integer.parseInt(f[i][2]));
				rv = rv.assign(regs[i], BigInteger.valueOf(v));
			}
			rv = rv.assign(valid, BigInteger.ONE);
			rv = rv.assign(fdly, BigInteger.valueOf(dly.getOrDefault(a, 0)));
			rv = rv.assign(wtop, BigInteger.valueOf(field(w, 71, 64)));
			rv = rv.assign(form, BigInteger.valueOf(field(w, 70, 67)));
			Address ad = code.getAddress(8L * a);
			pc.setRegisterValue(ad, ad.add(7), rv);
		}
		println(String.format("context set on %d words (%d padding words given the no-op record)", pr.r.size(), pad));

		Listing listing = currentProgram.getListing();
		for (Map.Entry<Integer, String> e : pr.line.entrySet()) {
			if (e.getKey() < n) {
				listing.setComment(code.getAddress(8L * e.getKey()), CommentType.EOL, e.getValue());
			}
		}

		SymbolTable st = currentProgram.getSymbolTable();
		TreeSet<Integer> entries = new TreeSet<>();
		entries.add(0);
		// Each source file of the line table starts a module: label its first
		// non-padding word with the file name.
		String lastFile = null;
		int modules = 0;
		for (Map.Entry<Integer, String> e : pr.line.entrySet()) {
			String file = e.getValue().substring(0, e.getValue().lastIndexOf(':'));
			if (file.equals(lastFile)) {
				continue;
			}
			lastFile = file;
			int a = e.getKey();
			while (pr.r.containsKey(a) && isPadding(pr.w.getOrDefault(a, BigInteger.ZERO), pr.r.get(a))) {
				a++;
			}
			if (!pr.r.containsKey(a)) {
				continue;
			}
			String lab = file.replaceAll("[^A-Za-z0-9_]", "_");
			st.createLabel(code.getAddress(8L * a), lab, SourceType.IMPORTED);
			entries.add(a);
			modules++;
		}
		println("source-file modules labelled: " + modules);
		// The dispatch table: word k of mgras_geif<variant>.u starts command k.
		String variant = base.startsWith("mgras_ge") ? base.substring(8) : base.startsWith("ge11") ? base.substring(4) : null;
		Path geif = null;
		if (variant != null) {
			geif = sibling(src, "mgras_geif" + variant + ".u");
			if (geif == null) {
				geif = sibling(src, "MG/mgras_geif" + variant + ".u");
			}
		}
		if (geif != null) {
			byte[] g = Files.readAllBytes(geif);
			int k = 0;
			for (int i = 0; i + 3 < g.length; i += 4) {
				int a = be32(g, i);
				if (a != 0 && pr.r.containsKey(a)) {
					st.createLabel(code.getAddress(8L * a), String.format("cmd_%03x", i / 4), SourceType.IMPORTED);
					entries.add(a);
					k++;
				}
			}
			println(geif.getFileName() + " command handlers: " + k);
		}
		String[] args = getScriptArgs();
		if (args.length > 0) {
			int k = 0;
			for (String l : Files.readAllLines(Paths.get(args[0]))) {
				String[] t = l.trim().replace("(", " ").replace(")", " ").split("\\s+");
				if (t.length >= 3 && t[0].equals("#define")) {
					t = new String[] { t[1], t[2] };
				}
				if (t.length != 2 || !t[1].startsWith("0x")) {
					continue;
				}
				int a = Long.decode(t[1]).intValue();
				if (pr.r.containsKey(a)) {
					st.createLabel(code.getAddress(8L * a), t[0], SourceType.IMPORTED);
					entries.add(a);
					k++;
				}
			}
			println("labels from " + args[0] + ": " + k);
		}
		// Special register 6, CHIP_REV, read at 0xfffe0018 by the revision
		// program (GE11-only, GE11.h). dmem counts 4-byte words.
		AddressSpace dm = af.getAddressSpace("dmem");
		MemoryBlock sb = mem.createUninitializedBlock("special", dm.getAddress(4L * 0xfffe0000L), 4L * 0x200, false);
		sb.setPermissions(true, true, false);
		sb.setVolatile(true);
		sb.setComment("special registers: register n at 0xfffe0000 + 4n");
		st.createLabel(dm.getAddress(4L * 0xfffe0018L), "CHIP_REV", SourceType.IMPORTED);

		// Decode every word first, in address order and without following
		// flow, so each transfer finds its delay-slot words already decoded;
		// the flow references the disassembler records then drive function
		// discovery from the entry points below.
		AddressSet all = new AddressSet(code.getAddress(0), code.getAddress(8L * n - 1));
		new DisassembleCommand(all, all, false).applyTo(currentProgram, monitor);
		// A constant store of a code address leaves Ghidra's reference there
		// and makes it lay a pointer over the word; clear those and decode
		// the words again.
		AddressSet redo = new AddressSet();
		for (int a = 0; a < n; a++) {
			Address ad = code.getAddress(8L * a);
			if (pr.r.containsKey(a) && listing.getInstructionContaining(ad) == null) {
				listing.clearCodeUnits(ad, ad.add(7), false);
				redo.add(ad, ad.add(7));
			}
		}
		if (!redo.isEmpty()) {
			new DisassembleCommand(redo, redo, false).applyTo(currentProgram, monitor);
			println("words decoded again after a pointer was laid over them: " + redo.getNumAddressRanges());
		}
		for (int a : entries) {
			Address ad = code.getAddress(8L * a);
			st.addExternalEntryPoint(ad);
			if (getFunctionAt(ad) == null) {
				createFunction(ad, null);
			}
		}
	}

	private void makeData(Memory mem, AddressFactory af, String sp, long words, String comment)
			throws Exception {
		AddressSpace s = af.getAddressSpace(sp);
		MemoryBlock b = mem.createUninitializedBlock(sp, s.getAddress(0), 4 * words, false);
		b.setPermissions(true, true, false);
		b.setComment(comment);
	}
}
