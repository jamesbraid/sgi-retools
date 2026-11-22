/* Apply the symbols of a Windows NT .dbg file to the PE image it was split from.
 *
 * A separate .dbg is an IMAGE_SEPARATE_DEBUG_HEADER, the section headers, the exported
 * names and a debug directory whose COFF entry points at the symbol table. Ghidra's PE loader
 * reads none of it. Symbol values are RVAs from the image base (a value at or above the
 * header's ImageBase is taken as a virtual address and rebased).
 *
 * Runs as a headless -preScript, so the names exist before analysis:
 *
 *   -preScript ReDbgImport.java FILE.dbg
 *
 * Counting rule, printed as "ReDbgImport: ..." at the end:
 *   - an auxiliary record is skipped, never counted;
 *   - a symbol whose type is a function (derived type 2) in the section named .text is a
 *     function; "functions" counts distinct addresses, so aliases of one address add none;
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
	static final int DEBUG_TYPE_COFF = 1;
	static final int DTYPE_FUNCTION = 2;

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
		for (int i = 0; i < sections; i++) {
			int at = HEADER_SIZE + i * SECTION_SIZE;
			int end = at;
			while (end < at + 8 && b.get(end) != 0) {
				end++;
			}
			byte[] raw = new byte[end - at];
			b.get(at, raw);
			text[i + 1] = new String(raw, StandardCharsets.US_ASCII).equals(".text");
		}

		int debugAt = HEADER_SIZE + sections * SECTION_SIZE + namesSize;
		int coffRaw = -1;
		for (int i = 0; i < debugSize / DEBUG_ENTRY_SIZE; i++) {
			int e = debugAt + i * DEBUG_ENTRY_SIZE;
			int type = b.getInt(e + 12);
			if (type == DEBUG_TYPE_COFF) {
				coffRaw = b.getInt(e + 24);
				break;
			}
		}
		if (coffRaw < 0) {
			throw new IllegalArgumentException(args[0] + " has no COFF symbol table");
		}
		readCoff(b, coffRaw, sections, text, imageBase);

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
			"ReDbgImport: COFF: %d symbol records, %d auxiliary skipped, %d functions, "
				+ "%d other labels, %d section names skipped, %d without a section, "
				+ "%d outside the image, %d names Ghidra rejects, %d functions not created",
			records, aux, functionAt.size(), labelAt.size(), skippedSections, ignored,
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
