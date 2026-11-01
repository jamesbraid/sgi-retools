// Decompile the functions at the given word addresses into OUTDIR/<addr>.c.
// Args: OUTDIR ADDR...
// @category GE11
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
			long w = Long.decode(a[i]);
			Address ad = code.getAddress(8 * w);
			Function f = getFunctionAt(ad);
			if (f == null) {
				disassemble(ad);
				f = createFunction(ad, null);
			}
			String text;
			if (f == null) {
				text = "// no function at " + a[i] + "\n";
			}
			else {
				DecompileResults r = d.decompileFunction(f, 300, monitor);
				text = r.decompileCompleted() ? r.getDecompiledFunction().getC()
						: "// decompile failed: " + r.getErrorMessage() + "\n";
			}
			try (PrintWriter out = new PrintWriter(new File(a[0], String.format("%04x.c", w)))) {
				out.print(text);
			}
		}
		d.dispose();
	}
}
