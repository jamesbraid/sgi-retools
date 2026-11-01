// Write every function Ghidra found: entry word address and name.
// Args: OUTFILE
// @category GE11
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class DumpFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("%04x\t%s%n", f.getEntryPoint().getAddressableWordOffset(), f.getName());
			}
		}
	}
}
