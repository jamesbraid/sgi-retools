/* Change the calling convention of functions, and the type of a parameter, before the decompile.
 *
 * Some code does not use the convention its debug information declares: a driver that passes its
 * context in ECX is described as __cdecl, so the decompile shows the context as a stack argument of
 * an unrelated type and no field names appear. This post-script reads a rule file, one rule per line:
 *
 *   callconv CONVENTION GLOB      set the calling convention of every function named GLOB
 *   param GLOB INDEX TYPE         set the type of parameter INDEX (from 0) of each such function
 *
 * GLOB is a function name with * as the wildcard, or @0xADDR for one function. CONVENTION is a
 * convention of the program's compiler spec, with or without its leading underscores and in either
 * case (fastcall, __fastcall). TYPE is a data type name as the Ghidra type parser reads it, such as
 * "__GLCOcontextRec *" or "unsigned int"; the type must already be in the program (a PDB puts its
 * types there). Rules apply in file order, so a callconv rule before a param rule gives the
 * parameter its new place first.
 *
 *   -postScript ReFunctionTypes.java RULES.tsv
 *
 * Fields are separated by a tab. Prints "ReFunctionTypes: ..." lines: one summary,
 * and one "FAILED" line for each rule that matched no function or could not be applied.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;

public class ReFunctionTypes extends GhidraScript {

	private static String bare(String convention) {
		return convention.replaceFirst("^_+", "").toLowerCase();
	}

	private List<Function> match(String glob) {
		List<Function> found = new ArrayList<>();
		if (glob.startsWith("@0x")) {
			Function f = getFunctionAt(toAddr(Long.decode(glob.substring(1))));
			if (f != null) {
				found.add(f);
			}
			return found;
		}
		StringBuilder regex = new StringBuilder();
		for (String part : glob.split("\\*", -1)) {
			if (regex.length() > 0) {
				regex.append(".*");
			}
			regex.append(Pattern.quote(part));
		}
		Pattern pattern = Pattern.compile(regex.toString());
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (pattern.matcher(f.getName()).matches()) {
				found.add(f);
			}
		}
		return found;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: ReFunctionTypes RULES.tsv");
		}
		DataTypeManager types = currentProgram.getDataTypeManager();
		DataTypeParser parser = new DataTypeParser(types, types, null,
			DataTypeParser.AllowedDataTypes.ALL);
		List<String> failed = new ArrayList<>();
		int convention = 0, typed = 0, rules = 0;
		for (String line : Files.readAllLines(Paths.get(args[0]))) {
			if (line.isBlank() || line.startsWith("#")) {
				continue;
			}
			rules++;
			String[] f = line.split("\t");
			if (!(f[0].equals("callconv") && f.length == 3) && !(f[0].equals("param") && f.length == 4)) {
				failed.add("not a rule: " + line.replace('\t', ' '));
				continue;
			}
			List<Function> functions = match(f[f[0].equals("callconv") ? 2 : 1]);
			if (functions.isEmpty()) {
				failed.add("no function matches " + line.replace('\t', ' '));
				continue;
			}
			if (f[0].equals("callconv")) {
				String name = null;
				for (PrototypeModel model : currentProgram.getCompilerSpec().getCallingConventions()) {
					if (bare(model.getName()).equals(bare(f[1]))) {
						name = model.getName();
					}
				}
				if (name == null) {
					failed.add("no calling convention " + f[1] + " in the compiler spec");
					continue;
				}
				for (Function function : functions) {
					if (!name.equals(function.getCallingConventionName())) {
						function.setCallingConvention(name);
						convention++;
					}
				}
			}
			else {
				DataType type;
				try {
					type = parser.parse(f[3]);
				}
				catch (Exception e) {
					failed.add("type " + f[3] + ": " + e.getMessage());
					continue;
				}
				int index = Integer.parseInt(f[2]);
				for (Function function : functions) {
					Parameter parameter = function.getParameter(index);
					if (parameter == null) {
						failed.add(function.getName() + " has no parameter " + index);
						continue;
					}
					parameter.setDataType(type, SourceType.USER_DEFINED);
					typed++;
				}
			}
		}
		for (String message : failed) {
			println("ReFunctionTypes: FAILED " + message);
		}
		println(String.format("ReFunctionTypes: %d rules, %d calling conventions changed, "
			+ "%d parameters typed, %d failed", rules, convention, typed, failed.size()));
	}
}
