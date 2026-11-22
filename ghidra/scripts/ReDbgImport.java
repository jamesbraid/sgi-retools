/* Apply the COFF symbols of a Windows NT .dbg file to the PE image it was split from.
 *
 * A separate .dbg is an IMAGE_SEPARATE_DEBUG_HEADER, the section headers, the exported
 * names and a debug directory whose COFF entry points at the symbol table. Ghidra's PE
 * loader reads none of it. Symbol values are RVAs from the image base (a value at or above the
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
 *   - any other named symbol in a section is a label (also counted by distinct address);
 *   - a symbol with no section (undefined, absolute, debug) or outside the image is ignored.
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
import java.util.HashSet;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

public class ReDbgImport extends GhidraScript {

	static final int SEPARATE_SIGNATURE = 0x4944;
	static final int HEADER_SIZE = 48, SECTION_SIZE = 40, DEBUG_ENTRY_SIZE = 28, SYMBOL_SIZE = 18;
	static final int DEBUG_TYPE_COFF = 1;
	static final int DTYPE_FUNCTION = 2;

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
		int symbolsAt = -1, count = 0;
		for (int i = 0; i < debugSize / DEBUG_ENTRY_SIZE; i++) {
			int e = debugAt + i * DEBUG_ENTRY_SIZE;
			if (b.getInt(e + 12) != DEBUG_TYPE_COFF) {
				continue;
			}
			int raw = b.getInt(e + 24);
			count = b.getInt(raw);
			symbolsAt = raw + b.getInt(raw + 4);
			break;
		}
		if (symbolsAt < 0) {
			throw new IllegalArgumentException(args[0] + " has no COFF symbol table");
		}
		int strings = symbolsAt + count * SYMBOL_SIZE;

		Address base = currentProgram.getImageBase();
		Set<Address> functionAt = new HashSet<>();
		Set<Address> labelAt = new HashSet<>();
		int records = 0, aux = 0, outside = 0, ignored = 0, badName = 0;
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
				continue;
			}
			if (value >= imageBase) {
				value -= imageBase;
			}
			Address at = base.add(value);
			MemoryBlock block = currentProgram.getMemory().getBlock(at);
			if (block == null || !block.isInitialized()) {
				outside++;
				continue;
			}
			boolean function = text[section] && ((type >> 4) & 0xf) == DTYPE_FUNCTION;
			if (!function) {
				if (labelAt.add(at) && getSymbolAt(at) == null && !label(at, name)) {
					badName++;
				}
				continue;
			}
			if (getSymbolAt(at) == null && !label(at, name)) {
				badName++;
			}
			if (functionAt.add(at)) {
				if (getInstructionAt(at) == null) {
					disassemble(at);
				}
				if (getFunctionAt(at) == null) {
					createFunction(at, null);
				}
			}
		}
		println(String.format(
			"ReDbgImport: %d symbol records, %d auxiliary skipped, %d functions, %d other labels, "
				+ "%d without a section, %d outside the image, %d names Ghidra rejects",
			records, aux, functionAt.size(), labelAt.size(), ignored, outside, badName));
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
