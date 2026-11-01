// Build a KONA-GE program from a geometry-engine microcode file.
//
// Run as an analyzeHeadless -preScript on a file imported raw:
//
//   analyzeHeadless DIR PROJ -import ucode/KONA/ge.u -loader BinaryLoader \
//     -processor KONA-GE:BE:32:default -preScript KonaGEImport.java
//
// Accepts ge.u (magic 0x45900003, 32-byte decoded records), ge11.u
// (0x45930003, 12-byte words) and ge.hex text (address and 18 hex digits).
// The decode needs both the 72-bit word W and the decoded record, so each
// file is paired with its sibling: X.u with X.hex, X.hex with X.u, ge11.u
// with ge.u. Code memory gets W[63:0], one 8-byte unit per word; the record
// groups and W[71:64] go into the context register at that word (see the
// header of kona_ge.slaspec for why). Padding words (W = 0 with record bits
// 8-62 clear) get the canonical no-op record, since W = 0 is a no-op word.
//
// Also: labels from a sibling ge_symbols, source file:line EOL comments from
// the .u line table, entry points at word 0 and at every handler address in
// a sibling geif.u, and uninitialised WRAM, CRAM and ERAM blocks.
//
// @category KONA

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

public class KonaGEImport extends GhidraScript {

	// Canonical no-op record (record of every form-0 word that is not padding).
	static final BigInteger NOP = new BigInteger(
		"894000180007fe007feb77febd0006fe4007ff00005c3e29c00", 16);

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
		Path recFile, wFile;
		if (magic == 0x45900003) {
			recFile = src;
			wFile = sibling(src, base + ".hex");
		}
		else if (magic == 0x45930003) {
			wFile = src;
			recFile = sibling(src, "ge.u");
		}
		else {
			wFile = src;
			recFile = sibling(src, base + ".u");
		}
		if (recFile == null) {
			throw new IOException(name + ": no decoded-record sibling (.u) beside it; the decode needs it");
		}
		readU(recFile, pr);
		if (wFile != null) {
			if (wFile.toString().endsWith(".hex")) {
				readHex(wFile, pr);
			}
			else {
				readU(wFile, pr);
			}
		}
		println(String.format("%s: %d records, %d words (records %s, words %s)", name, pr.r.size(),
			pr.w.size(), recFile.getFileName(), wFile == null ? "none" : wFile.getFileName()));
		for (Map.Entry<Integer, BigInteger> e : pr.w.entrySet()) {
			BigInteger r = pr.r.get(e.getKey());
			if (r == null) {
				throw new IOException(String.format("word 0x%04x has no record", e.getKey()));
			}
		}

		Memory mem = currentProgram.getMemory();
		for (MemoryBlock blk : mem.getBlocks()) {
			mem.removeBlock(blk, monitor);
		}
		AddressFactory af = currentProgram.getAddressFactory();
		AddressSpace code = af.getAddressSpace("code");
		int last = pr.r.lastKey();
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
		makeData(mem, af, "eram", 0x10000, "ERAM: external SRAM, size on KONA unknown");

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
		// most four (eight after a return or an end of command, both R88
		// transfers). See kona_ge.slaspec.
		Map<Integer, Integer> dly = new HashMap<>();
		for (Map.Entry<Integer, BigInteger> e : pr.r.entrySet()) {
			BigInteger r = e.getValue();
			long op = field(r, 86, 84);
			if (op == 6 || isPadding(pr.w.getOrDefault(e.getKey(), BigInteger.ZERO), r)) {
				continue;
			}
			boolean ret = (op == 4 || op == 5) && field(r, 88, 88) == 1;
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
		// The lane mask in force at each word (ucode/ge_isa.md "Lanes"): a word
		// with R77 clear sets it to R80-78 from the next word on. The setting
		// is carried in address order, which follows the straight-line code the
		// lane set-ups sit in; at a routine entry (word 0, a geif.u handler, a
		// call target) the caller's setting is not known, and all three lanes
		// are taken.
		Set<Integer> starts = new HashSet<>();
		starts.add(0);
		Path gf = sibling(recFile, "geif.u");
		if (gf != null && recFile.getFileName().toString().equals("ge.u")) {
			byte[] g = Files.readAllBytes(gf);
			for (int i = 0; i + 1 < g.length; i += 2) {
				starts.add(be16(g, i));
			}
		}
		for (Map.Entry<Integer, BigInteger> e : pr.r.entrySet()) {
			BigInteger r = e.getValue();
			long op = field(r, 86, 84);
			if ((op == 4 || op == 5) && field(r, 88, 88) == 0 && field(r, 76, 72) == 0) {
				long imm = field(r, 255, 224);
				starts.add((int) (field(r, 87, 87) == 1 ? e.getKey() + (int) imm : imm & 0xffff));
			}
		}
		Map<Integer, Integer> lmask = new HashMap<>();
		int cur = 7;
		for (Map.Entry<Integer, BigInteger> e : pr.r.entrySet()) {
			if (starts.contains(e.getKey())) {
				cur = 7;
			}
			lmask.put(e.getKey(), cur);
			BigInteger r = e.getValue();
			if (!isPadding(pr.w.getOrDefault(e.getKey(), BigInteger.ZERO), r) && field(r, 77, 77) == 0) {
				cur = (int) field(r, 80, 78);
			}
		}
		Register[] flm = { currentProgram.getRegister("flm0"), currentProgram.getRegister("flm1"),
			currentProgram.getRegister("flm2") };
		Register fdly = currentProgram.getRegister("fdly");
		Register valid = currentProgram.getRegister("fvalid");
		Register wtop = currentProgram.getRegister("fwtop");
		Register form = currentProgram.getRegister("fform");
		int pad = 0;
		monitor.initialize(n);
		monitor.setMessage("KONA-GE context");
		for (int a = 0; a < n; a++) {
			monitor.checkCancelled();
			monitor.setProgress(a);
			BigInteger r = pr.r.get(a);
			if (r == null) {
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
			for (int l = 0; l < 3; l++) {
				rv = rv.assign(flm[l], BigInteger.valueOf((lmask.get(a) >> l) & 1));
			}
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
		Path syms = sibling(recFile, "ge_symbols");
		Set<Integer> labelled = new HashSet<>();
		if (syms != null && Files.size(syms) > 0) {
			int k = 0;
			for (String l : Files.readAllLines(syms)) {
				String[] t = l.trim().split("\\s+");
				if (t.length == 2) {
					st.createLabel(code.getAddress(8L * Long.decode(t[1])), t[0], SourceType.IMPORTED);
					labelled.add(Long.decode(t[1]).intValue());
					k++;
				}
			}
			println("labels from ge_symbols: " + k);
		}

		// Entry points: the reset word and the command dispatch table.
		TreeSet<Integer> entries = new TreeSet<>();
		entries.add(0);
		Path geif = sibling(recFile, "geif.u");
		if (geif != null && recFile.getFileName().toString().equals("ge.u")) {
			byte[] g = Files.readAllBytes(geif);
			for (int i = 0; i + 1 < g.length; i += 2) {
				int a = be16(g, i);
				if (pr.r.containsKey(a)) {
					entries.add(a);
				}
			}
			println("geif.u handler addresses: " + (entries.size() - 1));
		}
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
		// Modules are chained through code addresses the program stores as
		// constants (form-15 constant stores, r215 = 3; ge_handlers.md).
		// Without a type on the symbols, a constant counts as a code address
		// when it is 0x100 or above and names a label of ge_symbols.
		int nconst = 0;
		for (Map.Entry<Integer, BigInteger> e : pr.r.entrySet()) {
			BigInteger r = e.getValue();
			int v = (int) field(r, 255, 224);
			if (field(r, 215, 214) == 3 && v >= 0x100 && labelled.contains(v) && entries.add(v)) {
				nconst++;
			}
		}
		println("module addresses loaded as constants: " + nconst);
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
