// Write what the import produced, for tests/check.py: one B line per memory
// block (name, start, size, initialised), one F line per function, and the
// number of symbols with the IMPORTED source.
// Args: OUTFILE
// @category RE
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class DumpMmsc extends GhidraScript {
	@Override
	protected void run() throws Exception {
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				out.printf("B\t%s\t0x%x\t%d\t%s%n", b.getName(),
					b.getStart().getOffset(), b.getSize(), b.isInitialized());
			}
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("F\t0x%x\t%s%n", f.getEntryPoint().getOffset(), f.getName());
			}
			int imported = 0;
			SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
			for (Symbol s : it) {
				if (s.getSource() == SourceType.IMPORTED) {
					imported++;
				}
			}
			out.printf("I\t%d%n", imported);
		}
	}
}
