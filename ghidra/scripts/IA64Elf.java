/* Prepare an IA-64 ELF object for analysis: seed r1 from __gp.
 *
 * Code addresses its data through r1 (addl r14=@gprel(x),r1; ld8 r14=[r14]),
 * and Ghidra's ELF loader has no IA-64 extension to set it.
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
