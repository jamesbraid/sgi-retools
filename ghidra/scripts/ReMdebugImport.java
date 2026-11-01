/* Apply the ECOFF-style .mdebug symbol table of a 32-bit MIPSpro object.
 *
 * Ghidra's ELF loader ignores .mdebug. For an o32 or N32 object built with the
 * MIPSpro compilers it holds the procedure names and addresses, the local labels,
 * the source file and line of every instruction run, and, for objects compiled
 * with -g, the full type information: structs, unions, enums, typedefs, the
 * signature of every procedure and its parameters and locals.
 *
 * The format is the public symbolic-header layout (binutils include/coff/sym.h,
 * symconst.h and ecoff.h). scripts/mdebug.py decodes it the same way and has the
 * format tests; the counts this script prints can be compared with
 * `python3 scripts/mdebug.py OBJECT`.
 *
 * Runs as a headless script with a phase argument:
 *
 *   -preScript  ReMdebugImport.java names [OBJECT]
 *       before analysis: procedure names and local labels, so the analysers
 *       disassemble from every routine and attribute calls to it;
 *   -postScript ReMdebugImport.java types [OBJECT]
 *       after analysis: line numbers, then the types in the category
 *       /mdebug/<object name>, procedure signatures and stack variables.
 *
 * OBJECT defaults to the imported file. Names and signatures that Ghidra already
 * holds from the object's own symbol tables are left alone: a name from .symtab
 * or .dynsym, or one a reader set, wins over .mdebug, and a function that already
 * has a user-defined signature keeps it. Everything this script adds carries the
 * IMPORTED source. An object without .mdebug, or an ELF64 object (which carries
 * DWARF instead), is reported and left untouched.
 *
 * Limits: the compiler records no parameter types for a pointer to function, so
 * those become pointers to a function returning the recorded type with no
 * parameters; `long` is 4 bytes (o32 and N32); a bit field that straddles its
 * storage unit is dropped; aggregates are matched across source files by tag, and
 * the first definition with members wins.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class ReMdebugImport extends GhidraScript {

	// Symbol types, storage classes, type qualifiers and basic types (symconst.h).
	static final int stGlobal = 1, stStatic = 2, stParam = 3, stLocal = 4, stLabel = 5, stProc = 6,
		stBlock = 7, stEnd = 8, stMember = 9, stTypedef = 10, stFile = 11, stStaticProc = 14,
		stStruct = 26, stUnion = 27, stEnum = 28, stIndirect = 34;
	static final int scNil = 0, scText = 1, scAbs = 5, scBits = 8, scInfo = 11, scRegister = 4;
	static final int tqPtr = 1, tqProc = 2, tqArray = 3, tqVol = 5, tqConst = 6;
	static final int btNil = 0, btAdr = 1, btChar = 2, btUChar = 3, btShort = 4, btUShort = 5,
		btInt = 6, btUInt = 7, btLong = 8, btULong = 9, btFloat = 10, btDouble = 11,
		btStruct = 12, btUnion = 13, btEnum = 14, btTypedef = 15, btRange = 16, btSet = 17,
		btComplex = 18, btDComplex = 19, btIndirect = 20, btVoid = 26, btLongLong = 27,
		btULongLong = 28;
	static final int INDEX_NIL = 0xfffff, ESCAPE_RFD = 0xfff;

	static class Fd {
		long adr;
		int rss, issBase, isymBase, csym, ilineBase, cline, ipdFirst, cpd, iauxBase, caux,
			rfdBase, crfd, lang, glevel, cbLineOffset, cbLine;
		String name;
		int index;
	}

	static class Sym {
		String name;
		long value;
		int st, sc, index, fd, isym;
	}

	static class Pdr {
		long adr;
		int isym, iline, lnLow, lnHigh, cbLineOffset;
		Fd fd;
		Sym sym;
		String name;
	}

	/** A decoded type: kind is base, ptr, func, array, struct, union, enum, typedef, range,
	 * const, volatile or bitfield. */
	static class T {
		String kind, name;
		T inner;
		int size, lo, hi, bits, fd = -1, isym = -1;
		boolean complete;

		T(String kind) {
			this.kind = kind;
		}
	}

	private ByteBuffer b;
	private int hdrOff;
	private boolean relocatable;
	private long delta;
	private final Map<String, Long> elfSectionAddr = new HashMap<>();
	private int lineOff, cbPd, cbSym, cbAux, cbSs, cbSsExt, cbFd, cbRfd, cbExt, ifdMax, ipdMax,
		iextMax;
	private Fd[] fds;
	private final List<Pdr> procs = new ArrayList<>();
	private final Map<Long, Sym> symCache = new HashMap<>();
	private final List<String> extNameList = new ArrayList<>();
	private final List<Sym> externals = new ArrayList<>();
	private DataTypeManager dtm;
	private CategoryPath cat;
	private final Map<String, DataType> byTag = new HashMap<>();
	private final Map<Long, DataType> aggByKey = new HashMap<>();
	private final Map<Long, DataType> typedefByKey = new HashMap<>();
	private final Map<String, DataType> typedefByName = new HashMap<>();
	private final Set<Long> typedefBusy = new HashSet<>();
	private final Map<Long, String> anonName = new HashMap<>();
	private int skippedMembers, droppedBitfields, brokenTypes;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String phase = args.length > 0 ? args[0] : "all";
		String path = args.length > 1 ? args[1] : currentProgram.getExecutablePath();
		if (!phase.equals("names") && !phase.equals("types") && !phase.equals("all")) {
			throw new IllegalArgumentException(
				"usage: ReMdebugImport <names|types|all> [OBJECT]");
		}
		byte[] raw;
		try {
			raw = Files.readAllBytes(Paths.get(path));
		}
		catch (Exception e) {
			println("re-mdebug: cannot read " + path + ": " + e);
			return;
		}
		b = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
		if (!locate(raw)) {
			return;
		}
		parseTables();
		println(String.format("re-mdebug: %s: %d files, %d procedures, %d externals",
			Paths.get(path).getFileName(), fds.length, procs.size(), iextMax));

		if (phase.equals("names") || phase.equals("all")) {
			applyNames();
		}
		if (phase.equals("types") || phase.equals("all")) {
			applyLines();
			String leaf = Paths.get(path).getFileName().toString();
			dtm = currentProgram.getDataTypeManager();
			cat = new CategoryPath("/mdebug/" + leaf.replace("/", "_"));
			buildTypes();
			applySignatures();
		}
	}

	// -- locating and reading the tables -------------------------------------------------

	private boolean locate(byte[] raw) {
		if (raw.length < 52 || raw[0] != 0x7f || raw[1] != 'E' || raw[2] != 'L' || raw[3] != 'F') {
			println("re-mdebug: not an ELF file");
			return false;
		}
		if (raw[4] != 1 || raw[5] != 2) {
			println("re-mdebug: not a 32-bit big-endian object (ELF64 objects carry DWARF)");
			return false;
		}
		int shoff = b.getInt(32);
		int shentsize = b.getShort(46) & 0xffff;
		int shnum = b.getShort(48) & 0xffff;
		int shstrndx = b.getShort(50) & 0xffff;
		relocatable = b.getShort(16) == 1;
		int stroff = b.getInt(shoff + shstrndx * shentsize + 16);
		int mdebugAt = -1;
		for (int i = 0; i < shnum; i++) {
			int sh = shoff + i * shentsize;
			int n = stroff + b.getInt(sh);
			int e = n;
			while (raw[e] != 0) {
				e++;
			}
			String nm = new String(raw, n, e - n);
			elfSectionAddr.put(nm, b.getInt(sh + 12) & 0xffffffffL);
			if (nm.equals(".mdebug")) {
				mdebugAt = sh;
			}
		}
		if (mdebugAt >= 0) {
			int sh = mdebugAt;
			{
				hdrOff = b.getInt(sh + 16);
				if (b.getInt(sh + 20) < 96) {
					println("re-mdebug: .mdebug is too small for its header");
					return false;
				}
				int magic = b.getShort(hdrOff) & 0xffff;
				if (magic != 0x7009 && magic != 0x1992) {
					println(String.format("re-mdebug: bad symbolic header magic %#x", magic));
					return false;
				}
				initDelta();
				return true;
			}
		}
		println("re-mdebug: no .mdebug section");
		return false;
	}

	private void parseTables() {
		int h = hdrOff + 4;
		// ilineMax cbLine cbLineOffset idnMax cbDnOffset ipdMax cbPdOffset isymMax cbSymOffset
		// ioptMax cbOptOffset iauxMax cbAuxOffset issMax cbSsOffset issExtMax cbSsExtOffset
		// ifdMax cbFdOffset crfd cbRfdOffset iextMax cbExtOffset
		lineOff = b.getInt(h + 8);
		ipdMax = b.getInt(h + 20);
		cbPd = b.getInt(h + 24);
		cbSym = b.getInt(h + 32);
		cbAux = b.getInt(h + 48);
		cbSs = b.getInt(h + 56);
		cbSsExt = b.getInt(h + 64);
		ifdMax = b.getInt(h + 68);
		cbFd = b.getInt(h + 72);
		cbRfd = b.getInt(h + 80);
		iextMax = b.getInt(h + 84);
		cbExt = b.getInt(h + 88);
		for (int i = 0; i < iextMax; i++) {
			int o = cbExt + 16 * i;
			Sym e = new Sym();
			e.name = cstr(cbSsExt + b.getInt(o + 4));
			e.value = b.getInt(o + 8) & 0xffffffffL;
			int w = b.getInt(o + 12);
			e.st = w >>> 26;
			e.sc = (w >>> 21) & 31;
			e.index = w & 0xfffff;
			e.fd = b.getShort(o + 2);
			e.isym = -1;
			externals.add(e);
			extNameList.add(e.name);
		}
		fds = new Fd[ifdMax];
		for (int i = 0; i < ifdMax; i++) {
			int o = cbFd + 72 * i;
			Fd f = new Fd();
			f.index = i;
			f.adr = b.getInt(o) & 0xffffffffL;
			f.rss = b.getInt(o + 4);
			f.issBase = b.getInt(o + 8);
			f.isymBase = b.getInt(o + 16);
			f.csym = b.getInt(o + 20);
			f.ilineBase = b.getInt(o + 24);
			f.cline = b.getInt(o + 28);
			f.ipdFirst = b.getShort(o + 40) & 0xffff;
			f.cpd = b.getShort(o + 42);
			f.iauxBase = b.getInt(o + 44);
			f.caux = b.getInt(o + 48);
			f.rfdBase = b.getInt(o + 52);
			f.crfd = b.getInt(o + 56);
			f.lang = b.getInt(o + 60) >>> 27;
			f.glevel = (b.getInt(o + 60) >>> 22) & 3;
			f.cbLineOffset = b.getInt(o + 64);
			f.cbLine = b.getInt(o + 68);
			f.name = f.rss == -1 ? "" : cstr(cbSs + f.issBase + f.rss);
			fds[i] = f;
		}
		for (Fd f : fds) {
			for (int p = f.ipdFirst; p < f.ipdFirst + f.cpd && p < ipdMax; p++) {
				int o = cbPd + 52 * p;
				Pdr d = new Pdr();
				d.fd = f;
				d.adr = b.getInt(o) & 0xffffffffL;
				d.isym = b.getInt(o + 4);
				d.iline = b.getInt(o + 8);
				d.lnLow = b.getInt(o + 40);
				d.lnHigh = b.getInt(o + 44);
				d.cbLineOffset = b.getInt(o + 48);
				d.name = "";
				if (f.rss != -1 && d.isym >= 0 && d.isym < f.csym) {
					d.sym = sym(f.index, d.isym);
					d.name = d.sym.name;
					if (d.sym.st != stProc && d.sym.st != stStaticProc && d.sym.st != stLabel) {
						d.sym = null;
					}
				}
				else if (d.isym >= 0 && d.isym < iextMax) {
					d.name = extNameList.get(d.isym);
				}
				procs.add(d);
			}
		}
	}

	private String cstr(int off) {
		int e = off;
		while (b.get(e) != 0) {
			e++;
		}
		byte[] t = new byte[e - off];
		b.get(off, t);
		return new String(t, java.nio.charset.StandardCharsets.ISO_8859_1);
	}

	private Sym sym(int fd, int isym) {
		long key = ((long) fd << 32) | isym;
		Sym s = symCache.get(key);
		if (s == null) {
			Fd f = fds[fd];
			if (isym < 0 || isym >= f.csym) {
				return null;
			}
			int o = cbSym + 12 * (f.isymBase + isym);
			s = new Sym();
			int iss = b.getInt(o);
			s.value = b.getInt(o + 4) & 0xffffffffL;
			int w = b.getInt(o + 8);
			s.st = w >>> 26;
			s.sc = (w >>> 21) & 31;
			s.index = w & 0xfffff;
			s.name = iss >= 0 ? cstr(cbSs + f.issBase + iss) : "";
			s.fd = fd;
			s.isym = isym;
			symCache.put(key, s);
		}
		return s;
	}

	private long aux(int fd, int i) {
		Fd f = fds[fd];
		if (i < 0 || i >= f.caux) {
			throw new IllegalStateException("aux " + i + " outside file " + fd);
		}
		return b.getInt(cbAux + 4 * (f.iauxBase + i)) & 0xffffffffL;
	}

	private int rfd(int fd, long r) {
		Fd f = fds[fd];
		if (f.rfdBase == 0 && f.crfd == 0) {
			return (int) r;
		}
		return b.getInt(cbRfd + 4 * (int) (f.rfdBase + r));
	}

	// -- addresses and names ----------------------------------------------------------

	/** How far Ghidra placed the image from the file's own addresses (an executable or library). */
	private void initDelta() {
		delta = 0;
		if (relocatable) {
			return;
		}
		Long at = elfSectionAddr.get(".text");
		MemoryBlock blk = currentProgram.getMemory().getBlock(".text");
		if (at != null && blk != null) {
			delta = blk.getStart().getOffset() - at;
		}
	}

	private static String sectionFor(int sc) {
		switch (sc) {
			case 1: return ".text";
			case 2: return ".data";
			case 3: return ".bss";
			case 13: return ".sdata";
			case 14: return ".sbss";
			case 15: return ".rodata";
			default: return null;
		}
	}

	/** Ghidra's address for a symbol value of the given storage class. */
	private Address mapAddr(long value, int sc) {
		if (!relocatable) {
			return address((value + delta) & 0xffffffffL);
		}
		String sec = sectionFor(sc);
		MemoryBlock blk = sec == null ? null : currentProgram.getMemory().getBlock(sec);
		return blk == null ? null : blk.getStart().add(value);
	}

	private Address address(long offset) {
		try {
			return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
		}
		catch (Exception outOfSpace) {
			return null;
		}
	}

	private boolean inImage(Address a) {
		MemoryBlock blk = a == null ? null : currentProgram.getMemory().getBlock(a);
		return blk != null && blk.isInitialized();
	}

	/** True when Ghidra already holds a name here that did not come from address guessing. */
	private boolean named(Address a) {
		Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
		return s != null && s.getSource() != SourceType.DEFAULT;
	}

	private void applyNames() throws Exception {
		int labelled = 0, kept = 0, functions = 0, outside = 0, labels = 0;
		for (Pdr p : procs) {
			if (p.name.isEmpty() || p.sym == null) {
				continue;
			}
			Address at = mapAddr(p.sym.value, scText);
			if (!inImage(at)) {
				outside++;
				continue;
			}
			if (named(at)) {
				kept++;
			}
			else {
				createLabel(at, p.name, true, SourceType.IMPORTED);
				labelled++;
			}
			if (getInstructionAt(at) == null) {
				disassemble(at);
			}
			if (getInstructionAt(at) != null && getFunctionAt(at) == null &&
				createFunction(at, null) != null) {
				functions++;
			}
		}
		// Local labels inside the procedures: branch targets the compiler named.
		for (Fd f : fds) {
			for (int i = 0; i < f.csym; i++) {
				Sym s = sym(f.index, i);
				if (s.st != stLabel || s.sc != scText || s.name.isEmpty()) {
					continue;
				}
				Address at = mapAddr(s.value, scText);
				if (!inImage(at) || named(at)) {
					continue;
				}
				try {
					createLabel(at, s.name, false, SourceType.IMPORTED);
					labels++;
				}
				catch (Exception e) {
					// a name clash inside the namespace: leave the address unnamed
				}
			}
		}
		// Named data: file-scope statics and external definitions.
		int data = 0;
		List<Sym> definitions = new ArrayList<>(externals);
		for (Fd f : fds) {
			for (int i = 0; i < f.csym; i++) {
				Sym s = sym(f.index, i);
				if (s.st == stStatic) {
					definitions.add(s);
				}
			}
		}
		for (Sym s : definitions) {
			if (s.name.isEmpty() || s.name.startsWith(".") || sectionFor(s.sc) == null ||
				s.sc == scText) {
				continue;
			}
			Address at = mapAddr(s.value, s.sc);
			if (at == null || currentProgram.getMemory().getBlock(at) == null || named(at)) {
				continue;
			}
			try {
				createLabel(at, s.name, true, SourceType.IMPORTED);
				data++;
			}
			catch (Exception e) {
				// leave it unnamed
			}
		}
		println(String.format("re-mdebug: %d procedure names applied, %d already named, " +
			"%d functions created, %d local labels, %d data names, %d outside the loaded image",
			labelled, kept, functions, labels, data, outside));
	}

	// -- line numbers ----------------------------------------------------------------

	private void applyLines() {
		SourceFileManager sfm = currentProgram.getSourceFileManager();
		int entries = 0, failed = 0, files = 0;
		for (Fd f : fds) {
			if (f.cbLine == 0 || f.name.isEmpty()) {
				continue;
			}
			SourceFile sf;
			try {
				// Ghidra wants an absolute path with no ".." or "." steps.
				String p = Paths.get("/").resolve(f.name).normalize().toString();
				sf = new SourceFile(p);
				sfm.addSourceFile(sf);
				files++;
			}
			catch (Exception e) {
				failed++;
				note("source file " + f.name, e);
				continue;
			}
			List<Pdr> mine = new ArrayList<>();
			for (Pdr p : procs) {
				if (p.fd == f) {
					mine.add(p);
				}
			}
			int base = lineOff + f.cbLineOffset;
			for (int j = 0; j < mine.size(); j++) {
				Pdr p = mine.get(j);
				if (p.iline == -1 || p.lnLow == -1 || p.lnHigh == -1) {
					continue;
				}
				int halt = base + (j + 1 < mine.size() ? mine.get(j + 1).cbLineOffset : f.cbLine);
				int o = base + p.cbLineOffset;
				long line = p.lnLow;
				long adr = p.sym != null ? p.sym.value : p.adr;
				while (o < halt) {
					int c = b.get(o++) & 0xff;
					int count = c & 15, delta = c >> 4;
					if (delta >= 8) {
						delta -= 16;
					}
					if (delta == -8) {
						delta = b.getShort(o);
						o += 2;
					}
					line += delta;
					Address at = mapAddr(adr, scText);
					if (line > 0 && inImage(at)) {
						try {
							sfm.addSourceMapEntry(sf, (int) line, at, 4L * (count + 1));
							entries++;
						}
						catch (Exception e) {
							failed++;
						}
					}
					adr += 4L * (count + 1);
				}
			}
		}
		println(String.format("re-mdebug: %d source files, %d line entries (%d skipped)", files,
			entries, failed));
	}

	// -- types -----------------------------------------------------------------------

	/** Decode the type record at aux index i of file fd; consumed[0] receives the words used. */
	private T typeAt(int fd, int i, int depth, int[] consumed) {
		if (i == INDEX_NIL) {
			consumed[0] = 0;
			return base("int", 4);
		}
		if (depth > 32) {
			throw new IllegalStateException("type nesting too deep");
		}
		long w = aux(fd, i);
		boolean fBit = (w >>> 31) != 0;
		boolean cont = ((w >>> 30) & 1) != 0;
		int bt = (int) ((w >>> 24) & 63);
		int[] tq = tqs(w);
		int n = 1;
		int width = 0;
		if (fBit) {
			width = (int) aux(fd, i + n);
			n++;
		}
		T t;
		if (bt == btIndirect) {
			long r = aux(fd, i + n);
			int rf = (int) (r >>> 20), idx = (int) (r & 0xfffff);
			n++;
			long rfv = rf;
			if (rf == ESCAPE_RFD) {
				rfv = aux(fd, i + n);
				n++;
			}
			if (rfv == 0xffffffffL) {
				t = base("int", 4);
			}
			else {
				t = typeAt(rfd(fd, rfv), idx, depth + 1, new int[1]);
			}
		}
		else if (bt == btStruct || bt == btUnion || bt == btEnum || bt == btSet ||
			bt == btTypedef || bt == btRange) {
			long r = aux(fd, i + n);
			int rf = (int) (r >>> 20), idx = (int) (r & 0xfffff);
			n++;
			long rfv = rf;
			if (rf == ESCAPE_RFD) {
				rfv = aux(fd, i + n);
				n++;
			}
			T ref = reference(fd, rfv, idx, bt, depth);
			if (bt == btRange) {
				T rg = new T("range");
				rg.name = ref.name;
				rg.lo = (int) aux(fd, i + n);
				rg.hi = (int) aux(fd, i + n + 1);
				n += 2;
				t = rg;
			}
			else {
				t = ref;
			}
		}
		else {
			t = basic(bt);
		}
		while (true) {
			for (int q : tq) {
				if (q == 0) {
					break;
				}
				if (q == tqPtr) {
					T p = new T("ptr");
					p.inner = t;
					t = p;
				}
				else if (q == tqProc) {
					T p = new T("func");
					p.inner = t;
					t = p;
				}
				else if (q == tqArray) {
					long r = aux(fd, i + n);
					int rf = (int) (r >>> 20);
					n++;
					if (rf == ESCAPE_RFD) {
						n++;
					}
					T a = new T("array");
					a.inner = t;
					a.lo = (int) aux(fd, i + n);
					a.hi = (int) aux(fd, i + n + 1);
					a.bits = (int) aux(fd, i + n + 2);
					n += 3;
					t = a;
				}
				else if (q == tqVol || q == tqConst) {
					T p = new T(q == tqVol ? "volatile" : "const");
					p.inner = t;
					t = p;
				}
			}
			if (!cont) {
				break;
			}
			w = aux(fd, i + n);
			n++;
			cont = ((w >>> 30) & 1) != 0;
			tq = tqs(w);
		}
		if (fBit) {
			T bf = new T("bitfield");
			bf.inner = t;
			bf.bits = width;
			t = bf;
		}
		consumed[0] = n;
		return t;
	}

	private static int[] tqs(long w) {
		return new int[] { (int) ((w >>> 12) & 15), (int) ((w >>> 8) & 15), (int) ((w >>> 4) & 15),
			(int) (w & 15), (int) ((w >>> 20) & 15), (int) ((w >>> 16) & 15) };
	}

	private static T base(String name, int size) {
		T t = new T("base");
		t.name = name;
		t.size = size;
		return t;
	}

	private static T basic(int bt) {
		switch (bt) {
			case btChar: return base("char", 1);
			case btUChar: return base("uchar", 1);
			case btShort: return base("short", 2);
			case btUShort: return base("ushort", 2);
			case btInt: case btLong: case 35: return base("int", 4);
			case btUInt: case btULong: case 36: return base("uint", 4);
			case btFloat: return base("float", 4);
			case btDouble: return base("double", 8);
			case btComplex: return base("complex8", 8);
			case btDComplex: return base("complex16", 16);
			case btVoid: return base("void", 0);
			case btLongLong: case 30: case 32: return base("longlong", 8);
			case btULongLong: case 31: case 33: return base("ulonglong", 8);
			case btAdr: case 34: return base("voidptr", 4);
			default: return base("int", 4);
		}
	}

	/** The aggregate or typedef a cross reference names. */
	private T reference(int fd, long rf, int idx, int bt, int depth) {
		String kind = bt == btStruct ? "struct" : bt == btUnion ? "union" : bt == btEnum ? "enum"
			: bt == btTypedef ? "typedef" : bt == btSet ? "set" : "range";
		T opaque = new T(kind);
		opaque.name = "";
		if (rf == 0xffffffffL || rf == ESCAPE_RFD && idx == 0) {
			return opaque;
		}
		int xfd = rfd(fd, rf);
		if (xfd < 0 || xfd >= fds.length || idx >= fds[xfd].csym) {
			return opaque;
		}
		Sym s = sym(xfd, idx);
		if (s.st == stIndirect || s.st == stTypedef && s.name.isEmpty()) {
			T t = typeAt(xfd, s.index, depth + 1, new int[1]);
			if (bt == btTypedef || t.kind.equals("struct") || t.kind.equals("union") ||
				t.kind.equals("enum")) {
				return t;
			}
			return opaque;
		}
		T t = new T(kind);
		t.name = s.name;
		t.fd = xfd;
		t.isym = idx;
		return t;
	}

	private String kindOf(Sym s, List<Sym> members) {
		if (s.st == stStruct) {
			return "struct";
		}
		if (s.st == stUnion) {
			return "union";
		}
		if (s.st == stEnum) {
			return "enum";
		}
		if (members.isEmpty()) {
			return "struct";
		}
		Sym first = members.get(0);
		boolean enumLike = first.index == INDEX_NIL || first.index == 0 && first.value == 0;
		if (!enumLike) {
			try {
				long w = aux(first.fd, first.index);
				int bt = (int) ((w >>> 24) & 63);
				enumLike = (bt == btNil || bt == btVoid || bt == btEnum && first.value == 0) &&
					((w >>> 12) & 15) == 0;
			}
			catch (Exception e) {
				enumLike = false;
			}
		}
		if (enumLike) {
			return "enum";
		}
		boolean allZero = members.size() > 1;
		for (Sym m : members) {
			if (m.value != 0) {
				allZero = false;
			}
		}
		return allZero ? "union" : "struct";
	}

	private List<Sym> membersOf(Sym s) {
		List<Sym> out = new ArrayList<>();
		Fd f = fds[s.fd];
		int j = s.isym + 1;
		int end = Math.min(s.index, f.csym);
		while (j < end) {
			Sym m = sym(s.fd, j);
			if (m.st == stMember) {
				out.add(m);
			}
			else if ((m.st == stBlock || m.st == stUnion || m.st == stEnum || m.st == stStruct) &&
				m.index != 0) {
				j = m.index - 1;
			}
			else if (m.st == stEnd) {
				break;
			}
			j++;
		}
		return out;
	}

	private static long key(int fd, int isym) {
		return ((long) fd << 32) | isym;
	}

	private void buildTypes() throws Exception {
		if (dtm.getCategory(cat) != null) {
			// A second run into the same program: replace nothing, add nothing.
			println("re-mdebug: category " + cat + " already exists; types not imported again");
			return;
		}
		// Pass 1: empty shells for every aggregate definition, one per tag.
		List<Sym> defs = new ArrayList<>();
		List<String> kinds = new ArrayList<>();
		for (Fd f : fds) {
			for (int i = 0; i < f.csym; i++) {
				Sym s = sym(f.index, i);
				boolean agg = s.st == stStruct || s.st == stUnion || s.st == stEnum ||
					s.st == stBlock && (s.sc == scInfo || s.sc == scNil) && s.index > i + 1;
				if (agg) {
					List<Sym> mem = membersOf(s);
					defs.add(s);
					kinds.add(kindOf(s, mem));
				}
			}
		}
		// An unnamed aggregate takes the name of the first typedef that gives it one.
		for (Fd f : fds) {
			for (int i = 0; i < f.csym; i++) {
				Sym s = sym(f.index, i);
				if (s.st != stTypedef || s.name.isEmpty()) {
					continue;
				}
				try {
					T t = typeAt(f.index, s.index, 0, new int[1]);
					if ((t.kind.equals("struct") || t.kind.equals("union") || t.kind.equals("enum")) &&
						t.fd >= 0) {
						Sym a = sym(t.fd, t.isym);
						if (a.name.isEmpty() || a.name.startsWith(".")) {
							anonName.putIfAbsent(key(t.fd, t.isym), s.name);
						}
					}
				}
				catch (Exception e) {
					// a typedef that cannot be decoded is reported when it is imported
				}
			}
		}
		int aggregates = 0, duplicates = 0, anon = 0;
		Map<String, Integer> bestDef = new HashMap<>();
		for (int d = 0; d < defs.size(); d++) {
			Sym s = defs.get(d);
			if (s.name.isEmpty() || s.name.startsWith(".")) {
				continue;
			}
			String k = kinds.get(d) + " " + s.name;
			int mem = membersOf(s).size();
			Integer prev = bestDef.get(k);
			if (prev == null || membersOf(defs.get(prev)).size() == 0 && mem > 0) {
				bestDef.put(k, d);
			}
		}
		for (int d = 0; d < defs.size(); d++) {
			Sym s = defs.get(d);
			String kind = kinds.get(d);
			boolean named = !(s.name.isEmpty() || s.name.startsWith("."));
			String k = kind + " " + s.name;
			if (named && byTag.containsKey(k)) {
				aggByKey.put(key(s.fd, s.isym), byTag.get(k));
				duplicates++;
				continue;
			}
			String tag = named ? s.name : anonName.getOrDefault(key(s.fd, s.isym),
				String.format("anon_%s_%d",
					leafName(fds[s.fd].name).replaceAll("[^A-Za-z0-9_]", "_"), s.isym));
			if (dtm.getDataType(cat, tag) != null) {
				// a struct, union and enum may share a tag in C; a category may not
				tag = tag + "_" + kind;
			}
			DataType dt;
			if (kind.equals("enum")) {
				dt = new EnumDataType(cat, tag, enumSize(s));
			}
			else if (kind.equals("union")) {
				dt = new UnionDataType(cat, tag, dtm);
			}
			else {
				dt = new StructureDataType(cat, tag, 0, dtm);
			}
			dt = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
			if (named) {
				byTag.put(k, dt);
			}
			else {
				anon++;
			}
			aggByKey.put(key(s.fd, s.isym), dt);
			aggregates++;
		}
		// Pass 2: fill each canonical definition.
		Set<DataType> filled = new HashSet<>();
		int filledCount = 0;
		for (int d = 0; d < defs.size(); d++) {
			Sym s = defs.get(d);
			DataType dt = aggByKey.get(key(s.fd, s.isym));
			if (dt == null || filled.contains(dt)) {
				continue;
			}
			boolean named = !(s.name.isEmpty() || s.name.startsWith("."));
			if (named && bestDef.get(kinds.get(d) + " " + s.name) != d) {
				continue;
			}
			filled.add(dt);
			try {
				fillAggregate(dt, s, kinds.get(d));
				filledCount++;
			}
			catch (Exception e) {
				brokenTypes++;
				println("re-mdebug: aggregate " + s.name + ": " + e);
			}
		}
		// Typedefs.
		int typedefs = 0;
		for (Fd f : fds) {
			for (int i = 0; i < f.csym; i++) {
				Sym s = sym(f.index, i);
				if (s.st == stTypedef && !s.name.isEmpty()) {
					if (typedefFor(f.index, i) != null) {
						typedefs++;
					}
				}
			}
		}
		println(String.format("re-mdebug: types in %s: %d aggregates (%d anonymous, %d duplicate " +
			"definitions merged), %d filled, %d typedefs, %d members skipped, %d bit fields " +
			"dropped, %d broken", cat, aggregates, anon, duplicates, filledCount,
			typedefs, skippedMembers, droppedBitfields, brokenTypes));
	}

	private int enumSize(Sym s) {
		int n = membersOf(s).size();
		return s.value == 0 || s.value == n ? 4 : (int) Math.max(1, Math.min(8, s.value));
	}

	private static String leafName(String p) {
		return p.substring(p.lastIndexOf('/') + 1);
	}

	private void fillAggregate(DataType dt, Sym s, String kind) throws Exception {
		List<Sym> mem = membersOf(s);
		if (dt instanceof ghidra.program.model.data.Enum) {
			ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
			for (Sym m : mem) {
				try {
					e.add(m.name, (int) m.value);
				}
				catch (Exception dup) {
					skippedMembers++;
				}
			}
			return;
		}
		if (dt instanceof Union) {
			Union u = (Union) dt;
			for (Sym m : mem) {
				T t = typeAt(m.fd, m.index, 0, new int[1]);
				try {
					if (t.kind.equals("bitfield")) {
						u.addBitField(toDataType(t.inner), t.bits, m.name, null);
					}
					else {
						DataType mt = toDataType(t);
						if (mt == null || mt.getLength() <= 0) {
							skippedMembers++;
							continue;
						}
						u.add(mt, m.name, null);
					}
				}
				catch (Exception ex) {
					skippedMembers++;
				}
			}
			return;
		}
		Structure st = (Structure) dt;
		int size = (int) s.value;
		if (size > 0) {
			st.growStructure(size);
		}
		for (Sym m : mem) {
			T t = typeAt(m.fd, m.index, 0, new int[1]);
			try {
				if (t.kind.equals("bitfield") || m.sc == scBits) {
					T inner = t.kind.equals("bitfield") ? t.inner : t;
					int width = t.kind.equals("bitfield") ? t.bits : inner.size * 8;
					DataType bt = toDataType(inner);
					int sz = bt == null ? 0 : bt.getLength();
					long bit = m.value;  // member offsets are in bits
					int unit = (int) (bit / (8L * sz));
					int inUnit = (int) (bit - unit * 8L * sz);
					if (sz <= 0 || inUnit + width > sz * 8) {
						droppedBitfields++;
						continue;
					}
					// Big-endian layout: the symbol's bit offset counts from the unit's top bit.
					int lsb = sz * 8 - inUnit - width;
					if ((unit + 1) * sz > st.getLength()) {
						st.growStructure((unit + 1) * sz - st.getLength());
					}
					st.insertBitFieldAt(unit * sz, sz, lsb, bt, width, m.name, null);
				}
				else {
					DataType mt = toDataType(t);
					if (mt == null || mt.getLength() <= 0) {
						skippedMembers++;
						continue;
					}
					int off = (int) (m.value / 8);
					if (off + mt.getLength() > st.getLength()) {
						st.growStructure(off + mt.getLength() - st.getLength());
					}
					st.replaceAtOffset(off, mt, mt.getLength(), m.name, null);
				}
			}
			catch (Exception ex) {
				skippedMembers++;
			}
		}
	}

	private DataType typedefFor(int fd, int isym) {
		long k = key(fd, isym);
		DataType have = typedefByKey.get(k);
		if (have != null) {
			return have;
		}
		Sym s = sym(fd, isym);
		DataType byName = typedefByName.get(s.name);
		if (byName != null) {
			typedefByKey.put(k, byName);
			return byName;
		}
		if (!typedefBusy.add(k)) {
			return null;
		}
		try {
			T t = typeAt(fd, s.index, 0, new int[1]);
			DataType target = toDataType(t);
			if (target == null || target.getLength() <= 0 && !(target instanceof Structure) &&
				!(target instanceof Union)) {
				return null;
			}
			if (target.getName().equals(s.name) && !(target instanceof TypeDef)) {
				// typedef struct foo foo, or a typedef that named an anonymous aggregate
				typedefByKey.put(k, target);
				typedefByName.put(s.name, target);
				return target;
			}
			String tdName = dtm.getDataType(cat, s.name) != null ? s.name + "_t" : s.name;
			DataType td = dtm.resolve(new TypedefDataType(cat, tdName, target, dtm),
				DataTypeConflictHandler.KEEP_HANDLER);
			typedefByKey.put(k, td);
			typedefByName.put(s.name, td);
			return td;
		}
		catch (Exception e) {
			brokenTypes++;
			return null;
		}
		finally {
			typedefBusy.remove(k);
		}
	}

	private DataType toDataType(T t) {
		switch (t.kind) {
			case "base":
				switch (t.name) {
					case "char": return CharDataType.dataType;
					case "uchar": return UnsignedCharDataType.dataType;
					case "short": return ShortDataType.dataType;
					case "ushort": return UnsignedShortDataType.dataType;
					case "int": return IntegerDataType.dataType;
					case "uint": return UnsignedIntegerDataType.dataType;
					case "float": return FloatDataType.dataType;
					case "double": return DoubleDataType.dataType;
					case "longlong": return LongLongDataType.dataType;
					case "ulonglong": return UnsignedLongLongDataType.dataType;
					case "void": return VoidDataType.dataType;
					case "voidptr": return pointer(VoidDataType.dataType);
					case "complex8": return Undefined8DataType.dataType;
					default: return Undefined.getUndefinedDataType(Math.max(1, t.size));
				}
			case "ptr": {
				DataType inner = toDataType(t.inner);
				return pointer(inner == null ? VoidDataType.dataType : inner);
			}
			case "func": {
				DataType ret = toDataType(t.inner);
				DataType r = ret == null ? VoidDataType.dataType : ret;
				FunctionDefinitionDataType f = new FunctionDefinitionDataType(
					cat.extend("fn"), "fn_returning_" + r.getName().replaceAll("[^A-Za-z0-9_]", "_"),
					dtm);
				f.setReturnType(r);
				return f;
			}
			case "array": {
				DataType el = toDataType(t.inner);
				int n = t.hi - t.lo + 1;
				if (el == null || el.getLength() <= 0 || n <= 0) {
					return null;
				}
				return new ArrayDataType(el, n, el.getLength());
			}
			case "const":
			case "volatile":
				return toDataType(t.inner);
			case "range":
				return IntegerDataType.dataType;
			case "bitfield":
				return toDataType(t.inner);
			case "struct":
			case "union":
			case "enum": {
				DataType dt = t.fd >= 0 ? aggByKey.get(key(t.fd, t.isym)) : null;
				if (dt == null && !t.name.isEmpty()) {
					dt = byTag.get(t.kind + " " + t.name);
				}
				if (dt == null) {
					// an opaque reference: an empty aggregate of that name
					String nm = t.name.isEmpty() ? "opaque" : t.name;
					DataType e = t.kind.equals("enum") ? new EnumDataType(cat, nm, 4)
						: t.kind.equals("union") ? new UnionDataType(cat, nm, dtm)
						: new StructureDataType(cat, nm, 0, dtm);
					dt = dtm.resolve(e, DataTypeConflictHandler.KEEP_HANDLER);
					if (!t.name.isEmpty()) {
						byTag.put(t.kind + " " + t.name, dt);
					}
				}
				return dt;
			}
			case "typedef": {
				if (t.fd >= 0) {
					DataType td = typedefFor(t.fd, t.isym);
					if (td != null) {
						return td;
					}
				}
				DataType byName = typedefByName.get(t.name);
				return byName != null ? byName : IntegerDataType.dataType;
			}
			default:
				return IntegerDataType.dataType;
		}
	}

	private int notes;

	/** Report the first few failures with their reason; the totals are in the summary. */
	private void note(String what, Exception e) {
		if (notes++ < 8) {
			println("re-mdebug: " + what + ": " + e);
		}
	}

	private DataType pointer(DataType target) {
		return new PointerDataType(target, currentProgram.getDefaultPointerSize(), dtm);
	}

	// -- procedures --------------------------------------------------------------------

	private void applySignatures() {
		int signatures = 0, locals = 0, kept = 0, failed = 0, params = 0, untyped = 0;
		for (Pdr p : procs) {
			if (p.sym == null || p.sym.st != stProc && p.sym.st != stStaticProc) {
				continue;
			}
			Address at = mapAddr(p.sym.value, scText);
			Function fn = at == null ? null : getFunctionAt(at);
			if (fn == null) {
				continue;
			}
			if (p.fd.glevel == 2) {
				// Compiled -g0 (GLEVEL_0): the table names the routine but records no types, so a
				// signature here would be the compiler's default, not information.
				untyped++;
				continue;
			}
			try {
				Fd f = p.fd;
				int fd = f.index;
				T ret = base("int", 4);
				int auxAt = p.sym.index;
				int symEnd = f.csym;
				if (auxAt != INDEX_NIL && auxAt < f.caux) {
					symEnd = Math.min(symEnd, (int) aux(fd, auxAt));
					T t = typeAt(fd, auxAt + 1, 0, new int[1]);
					ret = t.kind.equals("func") ? t.inner : t;
				}
				List<ParameterDefinitionImpl> defs = new ArrayList<>();
				List<Sym> stackLocals = new ArrayList<>();
				List<T> localTypes = new ArrayList<>();
				boolean varargs = false;
				Set<String> paramNames = new HashSet<>();
				for (int j = p.isym + 1; j < symEnd; j++) {
					Sym m = sym(fd, j);
					if (m.st == stEnd) {
						break;
					}
					if (m.name.isEmpty()) {
						continue;
					}
					if (m.st == stParam) {
						if (m.name.equals("...")) {
							varargs = true;
							continue;
						}
						DataType dt = toDataType(typeAt(fd, m.index, 0, new int[1]));
						if (dt == null || dt.getLength() <= 0) {
							dt = IntegerDataType.dataType;
						}
						defs.add(new ParameterDefinitionImpl(m.name, dt, null));
						paramNames.add(m.name);
					}
					else if (m.st == stLocal && m.sc == scAbs) {
						if (paramNames.contains(m.name)) {
							continue;   // the home slot of a parameter passed in a register
						}
						stackLocals.add(m);
						localTypes.add(typeAt(fd, m.index, 0, new int[1]));
					}
				}
				boolean userSignature = fn.getSignatureSource() == SourceType.USER_DEFINED;
				if (userSignature) {
					kept++;
				}
				else {
					DataType rt = toDataType(ret);
					FunctionDefinitionDataType sig = new FunctionDefinitionDataType(fn.getName());
					sig.setReturnType(rt == null ? VoidDataType.dataType : rt);
					sig.setArguments(defs.toArray(new ParameterDefinitionImpl[0]));
					sig.setVarArgs(varargs);
					ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(at, sig,
						SourceType.IMPORTED, false, FunctionRenameOption.NO_CHANGE);
					if (cmd.applyTo(currentProgram, monitor)) {
						signatures++;
						params += defs.size();
					}
					else {
						failed++;
						note("signature of " + p.name, new Exception(cmd.getStatusMsg()));
					}
				}
				for (int k = 0; k < stackLocals.size(); k++) {
					Sym m = stackLocals.get(k);
					DataType dt = toDataType(localTypes.get(k));
					if (dt == null || dt.getLength() <= 0 || m.sc != scAbs) {
						continue;
					}
					try {
						// The recorded offset is from the virtual frame pointer, which is the
						// stack pointer on entry: the same base as Ghidra's stack offsets.
						Variable v = new LocalVariableImpl(m.name, dt, (int) m.value,
							currentProgram, SourceType.IMPORTED);
						fn.addLocalVariable(v, SourceType.IMPORTED);
						locals++;
					}
					catch (Exception e) {
						failed++;
						note("local " + m.name + " of " + p.name, e);
					}
				}
			}
			catch (Exception e) {
				failed++;
				note("procedure " + p.name, e);
			}
		}
		println(String.format("re-mdebug: %d signatures applied (%d parameters), %d keep a " +
			"user-defined signature, %d stack variables, %d routines without type records " +
			"(compiled -g0), %d failures", signatures, params, kept, locals, untyped, failed));
	}
}
