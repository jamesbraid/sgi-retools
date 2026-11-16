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
 * void, gets a void return. One that sets r9 (then r10, r11) on every return path and never reads
 * it returns r8..r9 (..r11), the SAL convention of a status in r8 and values behind it.
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
		else if (setsOnEveryReturn(f, 8)) {
			// The decompiler can call such a function void (strcpy copies r32 to r8 and then
			// uses r8 as a pointer), and an open return would then commit as void.
			int regs = 1;
			while (regs < 4 && setsOnEveryReturn(f, 8 + regs) && !readsRegister(f, 8 + regs)) {
				regs++;
			}
			rt = Undefined.getUndefinedDataType(8 * regs);
		}
		else if (rt == null || proto.getReturnStorage() == null || proto.getReturnStorage().isVoidStorage()
				|| rt.getLength() > 8 || rt instanceof VoidDataType) {
			rt = DataType.DEFAULT;
		}
		else {
			rt = Undefined.getUndefinedDataType(rt.getLength());
		}
		// A void function keeps r8, so its callers keep what they had put there.
		String convention = rt instanceof VoidDataType ? "__stdcall_void"
				: currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
		f.updateFunction(convention,
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

	// Every return of f is reached with rN written: by an unpredicated instruction of f, or by a
	// call to a function that returns a value (for r9..r11, one that returns that many registers).
	// A predicated write, an indirect flow, a call to f itself or to a function with no known
	// return, and a function with no return, do not count. A value read again after the write is
	// a temporary, unless it copies an argument (strcpy stores through its r8 and returns it).
	boolean setsOnEveryReturn(Function f, int n) throws Exception {
		Register reg = currentProgram.getRegister("r" + n);
		Map<Address, Integer> in = new HashMap<>();
		Deque<Address> work = new ArrayDeque<>();
		in.put(f.getEntryPoint(), UNSET);
		work.add(f.getEntryPoint());
		boolean returns = false;
		while (!work.isEmpty()) {
			Address at = work.poll();
			Instruction ins = getInstructionAt(at);
			if (ins == null) {
				return false;
			}
			int st = in.get(at);
			PcodeOp[] ops = ins.getPcode();
			boolean predicated = false;
			boolean loads = false;
			for (PcodeOp op : ops) {
				loads |= op.getOpcode() == PcodeOp.LOAD;
				for (Varnode v : op.getInputs()) {
					if (st == FRESH && overlaps(v, reg)) {
						st = READ;
					}
				}
			}
			for (PcodeOp op : ops) {
				predicated |= op.getOpcode() == PcodeOp.CBRANCH;
				Varnode out = op.getOutput();
				if (!predicated && out != null && overlaps(out, reg)) {
					st = loads || !fromArguments(op) ? FRESH : ARGUMENT;
				}
			}
			FlowType ft = ins.getFlowType();
			Address[] flows = ins.getFlows();
			List<Address> next = new ArrayList<>();
			if (ft.isCall()) {
				boolean value = flows.length > 0;
				for (Address a : flows) {
					Function g = getFunctionAt(a);
					value &= g != null && g != f && returnsValue(g, n);
				}
				// A void callee leaves r8 as it was, but kills r9..r11.
				boolean leaves = flows.length > 0;
				for (Address a : flows) {
					Function g = getFunctionAt(a);
					leaves &= n == 8 && g != null && g != f && g.getReturnType() instanceof VoidDataType;
				}
				if (value && !predicated) {
					st = FRESH;
				}
				else if (!(leaves || (predicated && value && st != UNSET))) {
					st = UNSET;
				}
			}
			else if (ft.isTerminal()) {
				if (st == UNSET || st == READ) {
					return false;
				}
				returns = true;
			}
			else if (ft.isJump()) {
				if (flows.length == 0) {
					return false;
				}
				for (Address a : flows) {
					if (f.getBody().contains(a)) {
						next.add(a);
					}
					else {
						Function g = getFunctionAt(a);
						if ((st != UNSET && st != READ) || (g != null && g != f && returnsValue(g, n))) {
							returns = true;
						}
						else {
							return false;
						}
					}
				}
			}
			if (ft.isConditional() || ft.isFallthrough() || ft.isCall()) {
				Address ft2 = ins.getFallThrough();
				if (ft2 != null && f.getBody().contains(ft2)) {
					next.add(ft2);
				}
			}
			for (Address a : next) {
				Integer old = in.get(a);
				int joined = old == null ? st : join(old, st);
				if (old == null || joined != old) {
					in.put(a, joined);
					work.add(a);
				}
			}
		}
		return returns;
	}

	// The states of the register being tested for a return value, along a path.
	static final int UNSET = 0, FRESH = 1, READ = 2, ARGUMENT = 3;

	static int join(int a, int b) {
		if (a == UNSET || b == UNSET) {
			return UNSET;
		}
		return a == READ || b == READ ? READ : a == FRESH || b == FRESH ? FRESH : ARGUMENT;
	}

	// op reads only argument registers r32..r39 and constants.
	boolean fromArguments(PcodeOp op) {
		for (Varnode v : op.getInputs()) {
			if (v.isRegister()) {
				Register r = currentProgram.getRegister(v.getAddress(), v.getSize());
				if (r == null || !r.getName().matches("r3[2-9]")) {
					return false;
				}
			}
			else if (!v.isConstant()) {
				return false;
			}
		}
		return true;
	}

	boolean returnsValue(Function g) {
		return returnsValue(g, 8);
	}

	// g returns a value in rN: for r9..r11, a return as wide as r8..rN.
	boolean returnsValue(Function g, int n) {
		DataType t = g.getReturnType();
		return !(t instanceof VoidDataType) && t != DataType.DEFAULT
			&& (n == 8 || t.getLength() >= 8 * (n - 7));
	}

	static boolean overlaps(Varnode v, Register r) {
		return v.isRegister() && v.getAddress().getOffset() < r.getAddress().getOffset() + r.getNumBytes()
			&& v.getAddress().getOffset() + v.getSize() > r.getAddress().getOffset();
	}

	// Some instruction of f reads rN: a value written and read is a temporary, not a return value.
	boolean readsRegister(Function f, int n) {
		Register reg = currentProgram.getRegister("r" + n);
		for (Instruction in : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			for (PcodeOp op : in.getPcode()) {
				for (Varnode v : op.getInputs()) {
					if (overlaps(v, reg)) {
						return true;
					}
				}
			}
		}
		return false;
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
