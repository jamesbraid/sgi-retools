// Make the image read-only, as the PROM import does, and create a function at each address listed in a
// file (one 0x... address a line), last entry first, so a routine that runs on into the next stops there.
// Args: FUNCTIONS_FILE
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
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
    }
}
