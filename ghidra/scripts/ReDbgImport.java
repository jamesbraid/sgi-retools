/* Apply the symbols of a Windows NT .dbg file to the PE image it was split from.
 *
 * A separate .dbg is an IMAGE_SEPARATE_DEBUG_HEADER, the section headers, the exported
 * names and a debug directory. Ghidra's PE loader reads none of it. Two kinds of symbol are read:
 *
 *   - a COFF symbol table (debug type 1), used when the file has one;
 *   - otherwise the public symbols of a CodeView NB09 record (debug type 2, the sstGlobalPub
 *     subsection: S_PUB32 and S_PUB16 records). NB10 and NB11 records point at a .pdb, which is
 *     --pdb's job, and are refused with that message.
 *
 * Symbol values are RVAs from the image base (a COFF value at or above the header's ImageBase is
 * taken as a virtual address and rebased). A CodeView public is an offset in segment N, read as the
 * N-th section of the .dbg's own table.
 *
 * Runs as a headless -preScript, so the names exist before analysis:
 *
 *   -preScript ReDbgImport.java FILE.dbg
 *
 * Counting rule, printed as "ReDbgImport: ..." at the end:
 *   - a COFF auxiliary record is skipped, never counted;
 *   - a COFF symbol whose type is a function (derived type 2) in the section named .text is a
 *     function. A CodeView public carries no type, so one in a code section (the section has
 *     the code flag) is taken as a function, except a string literal (??_C@_...): an
 *     approximation, a data-in-code public of another kind would be misread. "functions" counts
 *     distinct addresses, so aliases of one address add none;
 *   - a name beginning with "." is a section name (the per-object ".text" and ".data" records)
 *     and is skipped, counted apart: it must never become the name of a function or label;
 *   - any other named symbol in a section is a label (also counted by distinct address);
 *   - a symbol with no section (undefined, absolute, debug) or outside the image is ignored.
 * Functions are named before labels, so a label at a function's address never takes its name.
 * A function symbol Ghidra cannot turn into a function (its address lies inside another
 * function's body) keeps its name as a label and is counted in "functions not created".
 * A name Ghidra already holds at an address (an export) is kept and not counted again.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ReDbgImport extends GhidraScript {

	static final int SEPARATE_SIGNATURE = 0x4944;
	static final int HEADER_SIZE = 48, SECTION_SIZE = 40, DEBUG_ENTRY_SIZE = 28, SYMBOL_SIZE = 18;
	static final int DEBUG_TYPE_COFF = 1, DEBUG_TYPE_CODEVIEW = 2;
	static final int DTYPE_FUNCTION = 2;
	static final int SCN_CODE = 0x20, SCN_EXECUTE = 0x20000000;
	static final int SST_GLOBAL_PUB = 0x12a;
	static final int S_PUB16 = 0x103, S_PUB32 = 0x203;

	private static class Sym {
		final String name;
		final long rva;
		final boolean function;

		Sym(String name, long rva, boolean function) {
			this.name = name;
			this.rva = rva;
			this.function = function;
		}
	}

	private int records, aux, skippedSections, ignored;
	private final List<Sym> symbols = new ArrayList<>();

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: ReDbgImport <file.dbg>");
		}
		ByteBuffer b = ByteBuffer.wrap(Files.readAllBytes(Paths.get(args[0])))
			.order(ByteOrder.LITTLE_ENDIAN);
		if ((b.getShort(0) & 0xffff) != SEPARATE_SIGNATURE) {
			throw new IllegalArgumentException(args[0] + " is not a separate .dbg file");
		}
		long imageBase = b.getInt(0x10) & 0xffffffffL;
		int sections = b.getInt(0x18);
		int namesSize = b.getInt(0x1c);
		int debugSize = b.getInt(0x20);

		boolean[] text = new boolean[sections + 1];
		boolean[] code = new boolean[sections + 1];
		long[] rva = new long[sections + 1];
		for (int i = 0; i < sections; i++) {
			int at = HEADER_SIZE + i * SECTION_SIZE;
			int end = at;
			while (end < at + 8 && b.get(end) != 0) {
				end++;
			}
			byte[] raw = new byte[end - at];
			b.get(at, raw);
			text[i + 1] = new String(raw, StandardCharsets.US_ASCII).equals(".text");
			rva[i + 1] = b.getInt(at + 12) & 0xffffffffL;
			int flags = b.getInt(at + 36);
			code[i + 1] = (flags & (SCN_CODE | SCN_EXECUTE)) != 0;
		}

		int debugAt = HEADER_SIZE + sections * SECTION_SIZE + namesSize;
		int coffRaw = -1, codeviewRaw = -1;
		for (int i = 0; i < debugSize / DEBUG_ENTRY_SIZE; i++) {
			int e = debugAt + i * DEBUG_ENTRY_SIZE;
			int type = b.getInt(e + 12);
			if (type == DEBUG_TYPE_COFF && coffRaw < 0) {
				coffRaw = b.getInt(e + 24);
			}
			else if (type == DEBUG_TYPE_CODEVIEW && codeviewRaw < 0) {
				codeviewRaw = b.getInt(e + 24);
			}
		}
		String kind;
		if (coffRaw >= 0) {
			kind = "COFF";
			readCoff(b, coffRaw, sections, text, imageBase);
		}
		else if (codeviewRaw >= 0) {
			kind = "CodeView NB09 publics";
			readCodeView(b, codeviewRaw, args[0], sections, code, rva);
		}
		else {
			throw new IllegalArgumentException(args[0] +
				" has no COFF symbol table and no CodeView debug record");
		}

		Address base = currentProgram.getImageBase();
		Set<Address> functionAt = new HashSet<>();
		Set<Address> labelAt = new HashSet<>();
		int outside = 0, badName = 0, notCreated = 0;
		// Highest address first, so a function's flow stops at the entry of the one after it.
		// Functions before labels, so a label at a function's address never takes its name.
		symbols.sort((x, y) -> Long.compare(y.rva, x.rva));
		for (int pass = 0; pass < 2; pass++) {
			for (Sym sym : symbols) {
				if (sym.function != (pass == 0)) {
					continue;
				}
				Address at = base.add(sym.rva);
				MemoryBlock block = currentProgram.getMemory().getBlock(at);
				if (block == null || !block.isInitialized()) {
					outside++;
					continue;
				}
				boolean fresh = (sym.function ? functionAt : labelAt).add(at);
				if (getSymbolAt(at) == null && !label(at, sym.name)) {
					badName++;
				}
				if (sym.function && fresh) {
					if (getInstructionAt(at) == null) {
						disassemble(at);
					}
					Function f = getFunctionAt(at);
					if (f == null) {
						f = createFunction(at, null);
					}
					if (f == null) {
						notCreated++;
					}
					nameFunction(f, sym.name);
				}
			}
		}
		println(String.format(
			"ReDbgImport: %s: %d symbol records, %d auxiliary skipped, %d functions, "
				+ "%d other labels, %d section names skipped, %d without a section, "
				+ "%d outside the image, %d names Ghidra rejects, %d functions not created",
			kind, records, aux, functionAt.size(), labelAt.size(), skippedSections, ignored,
			outside, badName, notCreated));
	}

	private void readCoff(ByteBuffer b, int raw, int sections, boolean[] text, long imageBase) {
		int count = b.getInt(raw);
		int symbolsAt = raw + b.getInt(raw + 4);
		int strings = symbolsAt + count * SYMBOL_SIZE;
		for (int i = 0; i < count; i++) {
			int s = symbolsAt + i * SYMBOL_SIZE;
			int naux = b.get(s + 17) & 0xff;
			records++;
			aux += naux;
			int section = b.getShort(s + 12);
			int type = b.getShort(s + 14) & 0xffff;
			long value = b.getInt(s + 8) & 0xffffffffL;
			String name = name(b, s, strings);
			i += naux;
			if (section <= 0 || section > sections || name.isEmpty()) {
				ignored++;
			}
			else if (name.startsWith(".")) {
				skippedSections++;
			}
			else {
				if (value >= imageBase) {
					value -= imageBase;
				}
				boolean function = text[section] && ((type >> 4) & 0xf) == DTYPE_FUNCTION;
				symbols.add(new Sym(name, value, function));
			}
		}
	}

	// NB09: "NB09", the offset of a directory of subsections; sstGlobalPub holds a header
	// (symbol hash, address hash, symbol size, two hash sizes) then S_PUB records.
	private void readCodeView(ByteBuffer b, int raw, String file, int sections, boolean[] code,
			long[] rva) {
		String sig = new String(new byte[] { b.get(raw), b.get(raw + 1), b.get(raw + 2),
			b.get(raw + 3) }, StandardCharsets.US_ASCII);
		if (!sig.equals("NB09")) {
			throw new IllegalArgumentException(file + " has no COFF symbol table; its CodeView " +
				"record is " + sig + ", which points at a .pdb (use --pdb) or is not supported " +
				"(only NB09 publics are read)");
		}
		int dir = raw + b.getInt(raw + 4);
		int headerSize = b.getShort(dir) & 0xffff, entrySize = b.getShort(dir + 2) & 0xffff;
		int entries = b.getInt(dir + 4);
		for (int i = 0; i < entries; i++) {
			int e = dir + headerSize + i * entrySize;
			if ((b.getShort(e) & 0xffff) != SST_GLOBAL_PUB) {
				continue;
			}
			int at = raw + b.getInt(e + 4);
			int size = b.getInt(at + 4);
			int p = at + 16, end = p + size;
			while (p + 4 <= end) {
				int length = b.getShort(p) & 0xffff;
				int type = b.getShort(p + 2) & 0xffff;
				if (type == S_PUB32 || type == S_PUB16) {
					int offSize = type == S_PUB32 ? 4 : 2;
					long off = type == S_PUB32 ? b.getInt(p + 4) & 0xffffffffL
						: b.getShort(p + 4) & 0xffffL;
					int section = b.getShort(p + 4 + offSize) & 0xffff;
					int nameAt = p + 4 + offSize + 2 + 2;
					int nameLen = b.get(nameAt) & 0xff;
					byte[] nameRaw = new byte[nameLen];
					b.get(nameAt + 1, nameRaw);
					String name = new String(nameRaw, StandardCharsets.ISO_8859_1);
					records++;
					if (section < 1 || section > sections || name.isEmpty()) {
						ignored++;
					}
					else if (name.startsWith(".")) {
						skippedSections++;
					}
					else {
						// String literals sit in the code segment of some builds; they are data.
						symbols.add(new Sym(name, rva[section] + off,
							code[section] && !name.startsWith("??_C@_")));
					}
				}
				p += 2 + length;
			}
			return;
		}
		throw new IllegalArgumentException(file + " has a CodeView NB09 record with no " +
			"sstGlobalPub subsection, so it holds no public symbols");
	}

	// createFunction keeps whatever primary symbol holds the address, so set the name outright.
	private void nameFunction(Function f, String name) throws Exception {
		if (f != null && !f.getName().equals(name) && f.getSymbol().getSource() == SourceType.DEFAULT) {
			try {
				f.setName(name, SourceType.IMPORTED);
			}
			catch (InvalidInputException | DuplicateNameException e) {
				// Ghidra refuses the name; the label attempt already counted it.
			}
		}
	}

	// Ghidra refuses a name with a control character (the \x7f import-descriptor markers).
	private boolean label(Address at, String name) throws Exception {
		try {
			createLabel(at, name, true, SourceType.IMPORTED);
			return true;
		}
		catch (InvalidInputException e) {
			return false;
		}
	}

	private String name(ByteBuffer b, int s, int strings) {
		int start, max;
		if (b.getInt(s) == 0) {
			start = strings + b.getInt(s + 4);
			max = b.limit() - start;
		}
		else {
			start = s;
			max = 8;
		}
		int end = start;
		while (end < start + max && b.get(end) != 0) {
			end++;
		}
		byte[] raw = new byte[end - start];
		b.get(start, raw);
		return new String(raw, StandardCharsets.ISO_8859_1);
	}
}
