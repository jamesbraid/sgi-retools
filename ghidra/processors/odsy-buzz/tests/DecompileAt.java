// Decompile the functions at the given records into OUTDIR/<record>.c.
// Args: OUTDIR RECORD...
// @category ODSY
import java.io.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DecompileAt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		new File(a[0]).mkdirs();
		AddressSpace code = currentProgram.getAddressFactory().getAddressSpace("code");
		DecompInterface d = new DecompInterface();
		d.openProgram(currentProgram);
		for (int i = 1; i < a.length; i++) {
			long r = Long.decode(a[i]);
			Function f = getFunctionAt(code.getAddress(8 * r));
			String text;
			if (f == null) {
				text = "// no function at record " + r + "\n";
			}
			else {
				DecompileResults res = d.decompileFunction(f, 300, monitor);
				text = res.decompileCompleted() ? res.getDecompiledFunction().getC()
						: "// decompile failed: " + res.getErrorMessage() + "\n";
			}
			try (PrintWriter out = new PrintWriter(new File(a[0], r + ".c"))) {
				out.print(text);
			}
		}
		d.dispose();
	}
}
