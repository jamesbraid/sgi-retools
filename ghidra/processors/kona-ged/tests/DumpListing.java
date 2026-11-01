// Write one line per program word: word index, the word, Ghidra's text for
// it; then one line per function (F word name).
// Args: OUTFILE
// @category KONA
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

public class DumpListing extends GhidraScript {
	@Override
	protected void run() throws Exception {
		MemoryBlock prog = currentProgram.getMemory().getBlock("program");
		Listing listing = currentProgram.getListing();
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (long a = 0; a < prog.getSize(); a += 4) {
				Address ad = prog.getStart().add(a);
				Instruction in = listing.getInstructionAt(ad);
				int w = currentProgram.getMemory().getInt(ad);
				out.printf("%03x\t%08x\t%s%n", a / 4, w, in == null ? "<none>" : in.toString());
			}
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("F\t%03x\t%s%n", f.getEntryPoint().getOffset() / 4, f.getName());
			}
		}
	}
}
