/* Apply names Ghidra's ELF loader ignores before it analyses.
 *
 * Runs as a headless -preScript, so it lands between import and analysis.
 * That order is the point: a function start Ghidra knows about before the
 * analysers run is a routine they disassemble from and attribute calls to,
 * where the same address found afterwards is just a label on bytes nobody
 * decoded.
 *
 * Ghidra's ELF loader applies .symtab and .dynsym but not .mdebug, which names
 * the static routines of an o32 or N32 library. tools/ghidra-export.py reads
 * those names and hands them over here.
 *
 * The table arrives as ADDRESS<tab>SIZE<tab>NAME, one symbol per line, in the
 * addresses Ghidra is using. Names are applied with the IMPORTED source, which
 * marks them as coming from the object's own table: a name Ghidra builds out of
 * an address is DEFAULT, and presenting one of those as though the object had
 * said it would be wrong.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

public class ReObjectSymbols extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException(
				"usage: ReObjectSymbols <symbols.tsv>");
		}
		List<String> lines = Files.readAllLines(Paths.get(args[0]),
			StandardCharsets.UTF_8);

		int labelled = 0;
		int functions = 0;
		int outside = 0;
		for (String line : lines) {
			if (line.startsWith("#") || line.isBlank()) {
				continue;
			}
			String[] fields = line.split("\t", 3);
			if (fields.length < 3) {
				continue;
			}
			Address at = address(Long.parseUnsignedLong(
				fields[0].replaceFirst("^0[xX]", ""), 16));
			MemoryBlock block = at == null
				? null : currentProgram.getMemory().getBlock(at);
			if (block == null || !block.isInitialized()) {
				outside++;
				continue;
			}
			createLabel(at, fields[2], true, SourceType.IMPORTED);
			labelled++;
			/* Disassembling here rather than leaving it to the analysers is
			 * what makes the name a function's name: createFunction needs an
			 * instruction at the entry, and a routine only ever reached
			 * through a pointer has nothing else pointing the decoder at it. */
			if (getInstructionAt(at) == null) {
				disassemble(at);
			}
			if (getInstructionAt(at) != null
					&& getFunctionAt(at) == null
					&& createFunction(at, null) != null) {
				functions++;
			}
		}
		println(String.format(
			"re-symbols: %d names applied, %d functions created, " +
			"%d outside the loaded image", labelled, functions, outside));
	}

	private Address address(long offset) {
		try {
			return currentProgram.getAddressFactory()
				.getDefaultAddressSpace().getAddress(offset);
		}
		catch (Exception outOfSpace) {
			return null;
		}
	}
}
