// Make a function with one int parameter and a structure type, run ReFunctionTypes.java on a rule
// file, then write the function's calling convention and first parameter type.
// Args: RULES OUTFILE
// @category RE
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class ReFunctionTypesCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Address at = currentProgram.getImageBase().add(0x1010);
		disassemble(at);
		Function f = createFunction(at, "alpha_one");
		f.addParameter(new ParameterImpl("p0", IntegerDataType.dataType, currentProgram),
			SourceType.USER_DEFINED);
		currentProgram.getDataTypeManager().addDataType(new StructureDataType("Ctx", 8), null);
		runScript("ReFunctionTypes.java", new String[] { args[0] });
		try (PrintWriter out = new PrintWriter(args[1])) {
			out.printf("alpha_one\t%s\t%s%n", f.getCallingConventionName(),
				f.getParameter(0).getDataType().getName());
		}
	}
}
