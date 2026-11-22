// Model analysis having marked a returning routine non-returning: make the callee a function with
// the no-return flag set, then disassemble the callers so each is cut at its call.
// Args: CALLEE_RVA CALLER_RVA... (hex, from the image base)
// @category RE
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ReReturningSetup extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		Address base = currentProgram.getImageBase();
		Address callee = base.add(Long.parseLong(args[0], 16));
		disassemble(callee);
		Function f = getFunctionAt(callee);
		if (f == null) {
			f = createFunction(callee, "callee");
		}
		f.setNoReturn(true);
		for (int i = 1; i < args.length; i++) {
			Address caller = base.add(Long.parseLong(args[i], 16));
			disassemble(caller);
			createFunction(caller, "caller" + i);
		}
	}
}
