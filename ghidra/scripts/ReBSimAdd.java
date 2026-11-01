/* Match the analysed program against a BSim database, then add it.
 *
 * Runs as a headless -postScript after analysis. Arguments:
 *   DATABASE_FILE   an H2 file database made by `bsim createdatabase`
 *   MATCHES_FILE    JSON lines written here, one per matched function
 *   MIN_SIMILARITY  0..1, matches below this are not written
 *
 * Matches are written only after the insert succeeds, in one append, so a
 * failed or repeated run leaves no rows behind. BSim keys an executable by
 * its bytes: loading the same file twice, under any label, fails at the
 * insert and nothing is written.
 *
 * Every function is queried against the executables already in the database
 * before this program is inserted, so loading N programs in turn yields each
 * pair of programs once, newer against older. A function's matches in its
 * own program are never reported.
 *
 * A BSim similarity is a score between two decompiled data-flow graphs, not
 * a finding: it says where two routines resemble each other. Whether they
 * are the same routine is settled by reading both.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ReBSimAdd extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        File h2 = new File(args[0]);
        double minimum = Double.parseDouble(args[2]);
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        BSimServerInfo info = new BSimServerInfo(h2.getAbsolutePath());
        int functions = 0, matched = 0;
        try (FunctionDatabase database = BSimClientFactory.buildClient(info, false)) {
            if (!database.initialize()) {
                throw new IllegalStateException(database.getLastError().message);
            }
            DatabaseInformation dbInfo = database.getInfo();
            GenSignatures gensig = new GenSignatures(dbInfo.trackcallgraph);
            try {
                gensig.setVectorFactory(database.getLSHVectorFactory());
                gensig.addExecutableCategories(dbInfo.execats);
                gensig.addFunctionTags(dbInfo.functionTags);
                gensig.addDateColumnName(dbInfo.dateColumnName);
                // The project is thrown away after the run, so there is no
                // repository to record; the label names the executable.
                gensig.openProgram(currentProgram, null, null, null,
                    "ghidra:/re", "/");
                FunctionManager manager = currentProgram.getFunctionManager();
                gensig.scanFunctions(manager.getFunctions(true), manager.getFunctionCount(), monitor);
                DescriptionManager descriptions = gensig.getDescriptionManager();
                descriptions.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());
                functions = descriptions.numFunctions();
                // The executable record's name is not always filled in before insert;
                // the program's own name is the label tools/ghidra-export.py imported it as.
                String own = currentProgram.getName();

                QueryNearest query = new QueryNearest();
                query.manage = descriptions;
                // Wide enough that one family's near-identical builds do not crowd
                // another family out of a function's list; the cut to the best two
                // per executable is made below.
                query.max = 200;
                query.thresh = minimum;
                query.signifthresh = 0.0;
                ResponseNearest response = query.execute(database);
                if (response == null) {
                    throw new IllegalStateException("query: " + database.getLastError().message);
                }
                StringBuilder rows = new StringBuilder();
                {
                    Iterator<SimilarityResult> results = response.result.iterator();
                    while (results.hasNext()) {
                        SimilarityResult result = results.next();
                        FunctionDescription base = result.getBase();
                        Iterator<SimilarityNote> notes = result.iterator();
                        Map<String, Integer> perExecutable = new LinkedHashMap<>();
                        while (notes.hasNext()) {
                            SimilarityNote note = notes.next();
                            FunctionDescription other = note.getFunctionDescription();
                            ExecutableRecord exe = other.getExecutableRecord();
                            if (exe.getNameExec().equals(own)) {
                                continue;
                            }
                            int seen = perExecutable.merge(exe.getNameExec(), 1, Integer::sum);
                            if (seen > 2) {
                                continue;
                            }
                            Map<String, Object> row = new LinkedHashMap<>();
                            row.put("exe", own);
                            row.put("function", base.getFunctionName());
                            row.put("address", "0x" + Long.toUnsignedString(base.getAddress(), 16));
                            row.put("match_exe", exe.getNameExec());
                            row.put("match_function", other.getFunctionName());
                            row.put("match_address", "0x" + Long.toUnsignedString(other.getAddress(), 16));
                            row.put("similarity", note.getSimilarity());
                            row.put("significance", note.getSignificance());
                            rows.append(gson.toJson(row)).append('\n');
                            matched++;
                        }
                    }
                }
                InsertRequest insert = new InsertRequest();
                insert.manage = descriptions;
                if (insert.execute(database) == null) {
                    throw new IllegalStateException("insert: " + database.getLastError().message);
                }
                Files.write(Paths.get(args[1]), rows.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
            finally {
                gensig.dispose();
            }
        }
        finally {
            BSimH2FileDataSource source = BSimH2FileDBConnectionManager.getDataSourceIfExists(info);
            if (source != null) {
                source.dispose();
            }
        }
        println("re-bsim: " + functions + " functions scanned, " + matched
            + " matches at or above " + minimum + ", program added");
    }
}
