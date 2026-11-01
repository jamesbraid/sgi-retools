// Write every function: entry record, name, and the record ranges of its body.
// Args: OUTFILE
// @category ODSY
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DumpFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				StringBuilder sb = new StringBuilder();
				for (AddressRange r : f.getBody()) {
					sb.append(String.format(" %d-%d", r.getMinAddress().getAddressableWordOffset(), r.getMaxAddress().getAddressableWordOffset()));
				}
				out.printf("%d\t%s\t%s%n", f.getEntryPoint().getAddressableWordOffset(), f.getName(), sb.toString().trim());
			}
		}
	}
}
