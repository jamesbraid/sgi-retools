/* Clear the no-return flag Ghidra's analysis put on a function, and repair its callers.
 *
 * When analysis marks a routine non-returning wrongly, every caller is cut at the call
 * ("Subroutine does not return"): the call was disassembled with no fall-through, so the code
 * after it was never reached and the decompiler drops it. This post-script names the routines that
 * do return, clears the flag, clears each call to them from the listing, disassembles it again so
 * the flow continues after it, and rebuilds the callers' bodies.
 *
 *   -postScript ReReturning.java NAME[,NAME...]
 *
 * A name is a function name or a virtual address written @0x...; run it after analysis and
 * before the decompiler export. Prints one "ReReturning: ..." line per function.
 *
 * Ghidra script, Apache-2.0 like Ghidra itself.
 *
 * @category RE
 */

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class ReReturning extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("usage: ReReturning NAME[,NAME...]");
		}
		for (String name : args[0].split(",")) {
			List<Function> found = new ArrayList<>();
			if (name.startsWith("@0x")) {
				Function f = getFunctionAt(toAddr(Long.decode(name.substring(1))));
				if (f != null) {
					found.add(f);
				}
			}
			else {
				found.addAll(getGlobalFunctions(name));
			}
			if (found.isEmpty()) {
				println("ReReturning: " + name + ": no such function");
			}
			for (Function f : found) {
				repair(name, f);
			}
		}
	}

	private void repair(String name, Function f) throws Exception {
		boolean was = f.hasNoReturn();
		f.setNoReturn(false);
		// Collect the sites first: re-disassembling changes the references being walked.
		List<Address> sites = new ArrayList<>();
		for (Reference ref : getReferencesTo(f.getEntryPoint())) {
			if (ref.getReferenceType().isCall() && getInstructionAt(ref.getFromAddress()) != null) {
				sites.add(ref.getFromAddress());
			}
		}
		Set<Address> callers = new LinkedHashSet<>();
		int open = 0;
		for (Address site : sites) {
			Instruction call = getInstructionAt(site);
			Function caller = getFunctionContaining(site);
			if (caller != null) {
				callers.add(caller.getEntryPoint());
			}
			// The call was disassembled as a terminator, with no fall-through to the next
			// instruction. Disassembling after it is not enough: clear the call and flow from it.
			Address next = call.getMaxAddress().add(1);
			currentProgram.getListing().clearCodeUnits(site, call.getMaxAddress(), false);
			disassemble(site);
			if (getInstructionAt(next) == null && currentProgram.getMemory().contains(next)) {
				open++;
			}
		}
		for (Address entry : callers) {
			Function caller = getFunctionAt(entry);
			if (caller != null) {
				CreateFunctionCmd.fixupFunctionBody(currentProgram, caller, monitor);
			}
		}
		println(String.format(
			"ReReturning: %s at %s was %s, %d call sites, %d callers rebuilt, %d sites with no code after the call",
			name, f.getEntryPoint(), was ? "no-return" : "returning", sites.size(), callers.size(),
			open));
	}
}
