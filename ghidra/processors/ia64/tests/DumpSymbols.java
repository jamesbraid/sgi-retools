// Write the program's labels, functions, memory blocks and r1 values, one per
// line: kind, address, then the name or value.
// Args: OUTFILE
// @category IA64
import java.io.PrintWriter;
import java.math.BigInteger;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

public class DumpSymbols extends GhidraScript {
	@Override
	protected void run() throws Exception {
		try (PrintWriter out = new PrintWriter(getScriptArgs()[0])) {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				out.printf("block\t%s\t%s\t%s%n", b.getStart(), b.getEnd(), b.getName());
			}
			for (Symbol s : currentProgram.getSymbolTable().getAllSymbols(true)) {
				if (s.getSource() == SourceType.IMPORTED) {
					out.printf("label\t%s\t%s%n", s.getAddress(), s.getName());
				}
			}
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				out.printf("function\t%s\t%s%n", f.getEntryPoint(), f.getName());
			}
			Register r1 = currentProgram.getRegister("r1");
			for (var r : currentProgram.getProgramContext().getRegisterValueAddressRanges(r1)) {
				BigInteger v = currentProgram.getProgramContext().getValue(r1, r.getMinAddress(), false);
				out.printf("r1\t%s\t%s\t%s%n", r.getMinAddress(), r.getMaxAddress(), v == null ? "-" : v.toString(16));
			}
			out.printf("instructions\t%d%n", currentProgram.getListing().getNumInstructions());
		}
	}
}
