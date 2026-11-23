// Create functions with exactly the bodies a curator gave, so analysis cannot merge or split them.
// Arguments: LIST.json [restore]
// LIST.json is an array of {"entry": "0x...", "end": "0x...", "name": "..."}: Ghidra addresses, end
// exclusive. Run as a pre-script, it makes each function (disassembling its body first). Run again as a
// post-script with "restore", it checks every body after analysis, puts back any that moved, and drops and
// reports any automatic function that overlaps one. The report line is
//   ReHandFunctions: N functions, M restored, K dropped
// @category RE
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ReHandFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        boolean restore = a.length > 1 && a[1].equals("restore");
        JsonArray list = JsonParser.parseString(Files.readString(Paths.get(a[0]), StandardCharsets.UTF_8)).getAsJsonArray();
        int restored = 0, dropped = 0;
        for (JsonElement element : list) {
            JsonObject item = element.getAsJsonObject();
            Address entry = toAddr(Long.parseUnsignedLong(item.get("entry").getAsString().substring(2), 16));
            Address last = toAddr(Long.parseUnsignedLong(item.get("end").getAsString().substring(2), 16) - 1);
            String name = item.get("name").getAsString();
            AddressSet body = new AddressSet(entry, last);
            Function now = getFunctionAt(entry);
            if (restore && now != null && now.getBody().equals(body)) continue;
            if (!restore) {
                new DisassembleCommand(body, null, true).applyTo(currentProgram, monitor);
            }
            List<Function> overlapping = new ArrayList<>();
            for (Function f : currentProgram.getFunctionManager().getFunctions(body, true)) overlapping.add(f);
            Function containing = getFunctionContaining(entry);
            if (containing != null && !overlapping.contains(containing)) overlapping.add(containing);
            for (Function f : overlapping) {
                if (f.getEntryPoint().equals(entry) && f.getBody().equals(body)) continue;
                if (restore && !f.getEntryPoint().equals(entry)) {
                    println("ReHandFunctions: dropped " + f.getName() + " at " + f.getEntryPoint() + ", it overlaps " + name);
                    dropped++;
                }
                currentProgram.getFunctionManager().removeFunction(f.getEntryPoint());
            }
            currentProgram.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
            if (restore) {
                println("ReHandFunctions: restored " + name + " at " + entry);
                restored++;
            }
        }
        println("ReHandFunctions: " + list.size() + " functions, " + restored + " restored, " + dropped + " dropped");
    }
}
