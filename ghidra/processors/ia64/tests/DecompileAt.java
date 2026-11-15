// Make a function at each address (disassembling from it) and decompile it
// into OUTDIR/<address>.c, with the listing beside it as <address>.s.
// Args: OUTDIR [r1=GP] ADDRESS...
// @category IA64
import java.io.*;
import java.math.BigInteger;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class DecompileAt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] a = getScriptArgs();
		new File(a[0]).mkdirs();
		int first = 1;
		if (a.length > 1 && a[1].startsWith("r1=")) {
			// The global pointer, for code that addresses its data through r1.
			AddressSetView all = currentProgram.getMemory();
			currentProgram.getProgramContext().setValue(currentProgram.getRegister("r1"),
				all.getMinAddress(), all.getMaxAddress(), new BigInteger(a[1].substring(5), 16));
			first = 2;
		}
		for (int i = first; i < a.length; i++) {
			Address ad = toAddr(a[i]);
			new DisassembleCommand(ad, null, true).applyTo(currentProgram, monitor);
			new CreateFunctionCmd(ad).applyTo(currentProgram, monitor);
		}
		DecompInterface d = new DecompInterface();
		d.openProgram(currentProgram);
		for (int i = first; i < a.length; i++) {
			Function f = getFunctionAt(toAddr(a[i]));
			String text;
			if (f == null) {
				text = "// no function at " + a[i] + "\n";
			}
			else {
				DecompileResults res = d.decompileFunction(f, 300, monitor);
				text = res.decompileCompleted() ? res.getDecompiledFunction().getC()
						: "// decompile failed: " + res.getErrorMessage() + "\n";
				try (PrintWriter out = new PrintWriter(new File(a[0], a[i] + ".s"))) {
					for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
						out.printf("%s\t%s%n", in.getAddress(), in.toString());
					}
				}
			}
			try (PrintWriter out = new PrintWriter(new File(a[0], a[i] + ".c"))) {
				out.print(text);
			}
		}
		d.dispose();
	}
}
