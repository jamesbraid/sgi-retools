// Write each function: name, entry and last address of its body (offsets from the image base), the
// number of instructions in the body and whether it is marked no-return.
// Args: OUTFILE
// @category RE
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionIterator;

public class DumpFunctionBodies extends GhidraScript {
	@Override
	protected void run() throws Exception {
		long base = currentProgram.getImageBase().getOffset();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				int count = 0;
				InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
				while (it.hasNext()) {
					it.next();
					count++;
				}
				out.printf("body\t%x\t%x\t%d\t%b\t%s%n", f.getEntryPoint().getOffset() - base,
					f.getBody().getMaxAddress().getOffset() - base, count, f.hasNoReturn(), f.getName());
			}
		}
	}
}
