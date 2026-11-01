// Write what KonaTypes.java applied, for tests/check.py: the data type at
// the start of SRAM (S), each typed token-list entry (T label type), and
// every function (F program name). Appends, so one file can take a run
// over many programs.
// Args: OUTFILE
// @category KONA
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class DumpTypes extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Listing listing = currentProgram.getListing();
		try (PrintWriter out = new PrintWriter(new java.io.FileWriter(getScriptArgs()[0], true))) {
			MemoryBlock sram = currentProgram.getMemory().getBlock("sram");
			if (sram != null) {
				Data d = listing.getDataAt(sram.getStart());
				out.printf("S\t%s%n", d == null ? "-" : d.getDataType().getPathName());
			}
			for (Symbol s : currentProgram.getSymbolTable().getSymbolIterator("icu_list_*", true)) {
				Data d = listing.getDataAt(s.getAddress());
				out.printf("T\t%s\t%s%n", s.getName(), d == null ? "-" : d.getDataType().getName());
			}
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("F\t%s\t%s%n", currentProgram.getName(), f.getName());
			}
		}
	}
}
