/* Prepare an IA-64 ELF object for analysis: seed r1 from __gp, and keep Ghidra
 * from deciding that functions do not return.
 *
 * Code addresses its data through r1 (addl r14=@gprel(x),r1; ld8 r14=[r14]),
 * and Ghidra's ELF loader has no IA-64 extension to set it. Linux's BUG() is a
 * printk call followed by `break 0` at the end of a function, so the code after
 * the call runs into the next function, and the non-returning discovery then
 * marks printk as never returning and cuts every caller short after it.
 * Runs as a headless -preScript. Args: none.
 *
 * @category IA64
 */

import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class IA64Elf extends GhidraScript {
	@Override
	protected void run() throws Exception {
		setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
		Symbol gp = getSymbols("__gp", null).stream().findFirst().orElse(null);
		if (gp == null) {
			printerr("IA64Elf: no __gp symbol");
			return;
		}
		BigInteger v = BigInteger.valueOf(gp.getAddress().getOffset());
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			if (b.isExecute()) {
				currentProgram.getProgramContext().setValue(currentProgram.getRegister("r1"), b.getStart(),
					b.getEnd(), v);
			}
		}
		println(String.format("IA64Elf: r1 = %#x", gp.getAddress().getOffset()));
	}
}
