// Write the program's imported functions and labels, one per line: kind, offset from the image base, name.
// Args: OUTFILE
// @category RE
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;

public class DumpDbgSymbols extends GhidraScript {
	@Override
	protected void run() throws Exception {
		long base = currentProgram.getImageBase().getOffset();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
				if (s.getSource() == SourceType.IMPORTED && s.getSymbolType() == SymbolType.LABEL) {
					out.printf("label\t%x\t%s%n", s.getAddress().getOffset() - base, s.getName());
				}
			}
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("function\t%x\t%s%n", f.getEntryPoint().getOffset() - base, f.getName());
			}
		}
	}
}
