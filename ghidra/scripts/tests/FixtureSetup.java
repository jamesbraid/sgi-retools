// Make the image read-only, as the PROM import does, and create a function at each address listed in a
// file (one 0x... address a line), last entry first, so a routine that runs on into the next stops there.
// With a second argument, the function there takes two 32-bit parameters, which -noanalysis would not infer.
// Args: FUNCTIONS_FILE [TWO_PARAMETER_FUNCTION]
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FixtureSetup extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) b.setWrite(false);
        List<Long> entries = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
            if (!line.trim().isEmpty()) entries.add(Long.decode(line.trim()));
        }
        Collections.reverse(entries);
        for (long e : entries) {
            disassemble(toAddr(e));
            createFunction(toAddr(e), null);
        }
        if (getScriptArgs().length > 1) {
            Function f = getFunctionAt(toAddr(Long.decode(getScriptArgs()[1])));
            List<Variable> params = new ArrayList<>();
            for (int i = 0; i < 2; i++) params.add(new ParameterImpl("a" + i, IntegerDataType.dataType, currentProgram));
            f.replaceParameters(params, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
        }
    }
}
