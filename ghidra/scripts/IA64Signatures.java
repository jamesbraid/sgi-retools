/* Give each IA-64 function the signature its own body shows, callees first.
 *
 * A call's p-code passes every output register of the caller's frame, so without
 * a known callee the decompiler takes any output set on some path as an argument.
 * This decompiles each function, keeps the parameters it reads from r32..r39 (no
 * more than its alloc's locals, which hold the inputs) and its r8 return, and
 * commits them; a call then passes exactly the callee's parameters.
 *
 * Runs as a headless -postScript after analysis; does nothing for another
 * processor or for a function whose signature came from symbols or a user.
 * Args: none for every function, or function names and 0x addresses to do just
 * those and the functions they call.
 * A function that never writes r8, and calls and jumps only to functions already committed as
 * void, gets a void return.
 *
 * @category IA64
 */

import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;

public class IA64Signatures extends GhidraScript {
	@Override
	protected void run() throws Exception {
		if (!currentProgram.getLanguage().getProcessor().toString().equals("IA64")) {
			return;
		}
		List<Function> order = new ArrayList<>();
		Set<Function> seen = new HashSet<>();
		String[] args = getScriptArgs();
		if (args.length == 0) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				postOrder(f, seen, order);
			}
		}
		else {
			for (String a : args) {
				Function f = a.startsWith("0x") ? getFunctionAt(toAddr(a)) : named(a);
				if (f == null || !seen.add(f)) {
					continue;
				}
				for (Function g : f.getCalledFunctions(monitor)) {
					if (seen.add(g)) {
						order.add(g);
					}
				}
				order.add(f);
			}
		}
		DecompInterface d = new DecompInterface();
		d.openProgram(currentProgram);
		int done = 0;
		for (Function f : order) {
			monitor.checkCancelled();
			if (f.isThunk() || f.isExternal() || f.getSignatureSource() != SourceType.DEFAULT) {
				continue;
			}
			DecompileResults r = d.decompileFunction(f, 60, monitor);
			if (r.decompileCompleted() && commit(f, r.getHighFunction())) {
				done++;
			}
		}
		d.dispose();
		println(String.format("IA64Signatures: %d of %d functions", done, order.size()));
	}

	// Callees before callers, so a caller's decompilation already sees them; a
	// cycle is broken where it is first met.
	void postOrder(Function root, Set<Function> seen, List<Function> order) throws Exception {
		Deque<Iterator<Function>> stack = new ArrayDeque<>();
		Deque<Function> owners = new ArrayDeque<>();
		if (!seen.add(root)) {
			return;
		}
		stack.push(root.getCalledFunctions(monitor).iterator());
		owners.push(root);
		while (!stack.isEmpty()) {
			Iterator<Function> it = stack.peek();
			if (it.hasNext()) {
				Function g = it.next();
				if (seen.add(g)) {
					stack.push(g.getCalledFunctions(monitor).iterator());
					owners.push(g);
				}
			}
			else {
				stack.pop();
				order.add(owners.pop());
			}
		}
	}

	Function named(String name) {
		List<Function> fs = getGlobalFunctions(name);
		return fs.size() == 1 ? fs.get(0) : null;
	}

	boolean commit(Function f, HighFunction hf) throws Exception {
		FunctionPrototype proto = hf.getFunctionPrototype();
		DataType[] types = new DataType[8];
		boolean[] spilled = new boolean[8];
		int count = 0;
		for (int i = 0; i < proto.getNumParams(); i++) {
			HighSymbol p = proto.getParam(i);
			Register reg = p.getStorage().getRegister();
			int n = reg == null ? -1 : stacked(reg.getName());
			if (n >= 0 && n < 8) {
				types[n] = p.getDataType();
				spilled[n] = onlyStored(p.getHighVariable());
				count = Math.max(count, n + 1);
			}
		}
		count = Math.min(count, allocLocals(f));
		// A varargs function stores every input from some point on to the stack,
		// for va_arg to walk: those are not parameters a caller always passes.
		int fixed = count;
		while (count == 8 && fixed > 0 && spilled[fixed - 1]) {
			fixed--;
		}
		boolean varargs = fixed < count && count - fixed > 1;
		if (varargs) {
			count = fixed;
		}
		// Sizes only: a type the decompiler guessed would be locked in for every caller.
		List<Variable> params = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			int size = types[i] != null && types[i].getLength() <= 8 ? types[i].getLength() : 8;
			params.add(new ParameterImpl("param_" + (i + 1), Undefined.getUndefinedDataType(size),
				currentProgram));
		}
		// With no r8 return, leave the return open rather than void: a caller that returns
		// through complementary predicated writes still needs a possible r8 from the call.
		DataType rt = proto.getReturnType();
		if (neverWritesR8(f)) {
			rt = VoidDataType.dataType;
		}
		else if (rt == null || proto.getReturnStorage() == null || proto.getReturnStorage().isVoidStorage()
				|| rt.getLength() > 8 || rt instanceof VoidDataType) {
			rt = DataType.DEFAULT;
		}
		else {
			rt = Undefined.getUndefinedDataType(rt.getLength());
		}
		f.updateFunction(currentProgram.getCompilerSpec().getDefaultCallingConvention().getName(),
			new ReturnParameterImpl(rt, currentProgram), params,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		f.setVarArgs(varargs);
		return true;
	}

	// No instruction of f writes r8, and every call or jump out of f goes to a function this
	// script already made void: nothing can leave a value there for the caller.
	boolean neverWritesR8(Function f) throws Exception {
		Register r8 = currentProgram.getRegister("r8");
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			for (PcodeOp op : in.getPcode()) {
				Varnode out = op.getOutput();
				if (out != null && out.isRegister() && out.getAddress().equals(r8.getAddress())) {
					return false;
				}
			}
			FlowType ft = in.getFlowType();
			Address[] flows = in.getFlows();
			if (!ft.isCall() && !(ft.isJump() && (flows.length != 1 || !f.getBody().contains(flows[0])))) {
				continue;
			}
			if (flows.length == 0) {
				return false;
			}
			for (Address a : flows) {
				Function g = getFunctionAt(a);
				if (g == null || g == f || !(g.getReturnType() instanceof VoidDataType)) {
					return false;
				}
			}
		}
		return true;
	}

	// The incoming value goes only to stack slots, through copies and merges, and is
	// never computed with: a varargs spill.
	static boolean onlyStored(HighVariable v) {
		if (v == null) {
			return false;
		}
		for (Varnode vn : v.getInstances()) {
			if (vn.isInput()) {
				return stored(vn, new HashSet<>());
			}
		}
		return false;
	}

	static boolean stored(Varnode vn, Set<Varnode> seen) {
		if (!seen.add(vn)) {
			return true;
		}
		Iterator<PcodeOp> it = vn.getDescendants();
		while (it.hasNext()) {
			PcodeOp op = it.next();
			int opc = op.getOpcode();
			if (opc == PcodeOp.STORE && op.getInput(2) == vn) {
				continue;
			}
			Varnode out = op.getOutput();
			boolean pass = opc == PcodeOp.COPY || opc == PcodeOp.CAST || opc == PcodeOp.INDIRECT
				|| opc == PcodeOp.MULTIEQUAL;
			if (!pass || out == null || !(out.isUnique() || out.getAddress().isStackAddress())
					|| !stored(out, seen)) {
				return false;
			}
		}
		return true;
	}

	static int stacked(String name) {
		if (!name.matches("r3[2-9]")) {
			return -1;
		}
		return Integer.parseInt(name.substring(1)) - 32;
	}

	// The inputs are among the locals of the frame the entry's alloc makes; with
	// no alloc in the entry bundle the function keeps its caller's outputs.
	int allocLocals(Function f) {
		Instruction in = getInstructionAt(f.getEntryPoint());
		for (int i = 0; i < 3 && in != null; i++, in = in.getNext()) {
			if (in.getMnemonicString().equals("alloc")) {
				// Operands r1, sof, sol, sor: ar.pfs is part of the syntax.
				return (int) in.getScalar(2).getValue();
			}
		}
		return 8;
	}
}
