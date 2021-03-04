package v8_bytecode;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class V8_PcodeOpEmitter {
	static final String RAM = "ram";

	private HashMap<String, Varnode> nameToReg;
	private ArrayList<PcodeOp> opList;
	private SleighLanguage language;
	private AddressSpace defSpace;
	private AddressSpace constSpace;
	private AddressSpace uniqueSpace;
	private Varnode spVarnode;
	private Varnode accVarnode;
	private Varnode defSpaceId;
	private long uniqueBase;
	private Address opAddress;
	private int seqnum;

	private Varnode convertRegisterToVarnode(Register reg) {
		Varnode vn = new Varnode(reg.getAddress(), reg.getBitLength() / 8);
		return vn;
	}

	private String findTempName(Address addr) {
		if (addr.getAddressSpace() != uniqueSpace) {
			return null;
		}
		for (Entry<String, Varnode> entry : nameToReg.entrySet()) {
			if (entry.getValue().getAddress().equals(addr)) {
				return entry.getKey();
			}
		}
		return null;
	}

	private Varnode findRegister(String name) {
		Varnode vn = nameToReg.get(name);
		if (vn != null) {
			return vn;
		}
		Register reg = language.getRegister(name);
		if (reg == null) {
			throw new IllegalArgumentException("Register must already exist: " + name);
		}
		vn = convertRegisterToVarnode(reg);
		nameToReg.put(name, vn);
		return vn;
	}

	private Varnode findVarnode(String name, int size) {
		Varnode vn = nameToReg.get(name);
		if (vn != null) {
			if (vn.getSize() != size) {
				throw new IllegalArgumentException("Cannot find varnode: " + name);
			}
			return vn;
		}
		Register reg = language.getRegister(name);
		if (reg != null) {
			if (reg.getBitLength() == size * 8) {
				vn = convertRegisterToVarnode(reg);
				nameToReg.put(name, vn);
				return vn;
			}
		}
		vn = new Varnode(uniqueSpace.getAddress(uniqueBase), size);
		uniqueBase += 16;
		nameToReg.put(name, vn);
		return vn;
	}

	private Varnode constantOrRegister(String name) {
		if (name.charAt(0) <= '9') {
			long val = Long.decode(name);
			return getConstant(val, 8);
		}
		return findRegister(name);
	}

	private Varnode getConstant(long val, int size) {
		return new Varnode(constSpace.getAddress(val), size);
	}

	private int findOpCode(String name) {
		if (name.equals("cpool")) {
			return PcodeOp.CPOOLREF;
		}
		return PcodeOp.COPY;
	}

	public V8_PcodeOpEmitter(SleighLanguage language, Address opAddr, long uniqBase) {
		Method getSpaceId = null;
		nameToReg = new HashMap<String, Varnode>();
		opList = new ArrayList<PcodeOp>();
		this.language = language;
		constSpace = language.getAddressFactory().getConstantSpace();
		defSpace = language.getDefaultSpace();
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
		uniqueBase = uniqBase;
		opAddress = opAddr;
		seqnum = 0; 
		spVarnode = findRegister("sp");
		accVarnode = findRegister("acc");
		String aGetSpaceID = "getSpaceID";
		String aGetBaseSpaceID = "getBaseSpaceID";
		try {
			getSpaceId = defSpace.getClass().getMethod(aGetSpaceID, (Class<?>[])null);
		} catch (NoSuchMethodException | SecurityException e1) {	
		}
		try {
			getSpaceId = defSpace.getClass().getMethod(aGetBaseSpaceID, (Class<?>[])null);
		} catch (NoSuchMethodException | SecurityException e1) {	
		}
		int id;
		try {
			id = (int) getSpaceId.invoke(defSpace);
			defSpaceId = getConstant(id, 4);
		} catch (Exception e) {}
	}

	public PcodeOp[] getPcodeOps() {
		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);
		return res;
	}

	public void defineTemp(String name, int size) {
		Varnode vn = findVarnode(name, size);
		if (!vn.isUnique() || vn.getSize() != size) {
			throw new IllegalArgumentException("Name is already assigned: " + name);
		}
	}

	/**
	 * Emits pcode to push a value of computational category 1 onto the stack.
	 * @param valueName - name of varnode to push.
	 */
	public void emitPushCat1Value(String valueName) {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(4, spVarnode.getSize());
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, in, spVarnode);
		opList.add(op);
		in = new Varnode[3];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		in[2] = findRegister(valueName);
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.STORE, in);
		opList.add(op);
	}

	/**
	 * Emits pcode to push a value of computational category 2 onto the stack.
	 * @param valueName - name of varnode to push.
	 */
	public void emitPushCat2Value(String valueName) {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, in, spVarnode);
		opList.add(op);
		in = new Varnode[3];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		in[2] = findRegister(valueName);
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.STORE, in);
		opList.add(op);
	}

	/**
	 * Emits pcode to pop a value of computational category 2 from the stack.
	 * @param destName - name of destination varnode.
	 */
	public void emitPopCat2Value(String destName) {
		Varnode out = findVarnode(destName, 8);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
		in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}

	/**
	 * Emits pcode to pop a value of computational category 1 from the stack.
	 * @param destName - name of destination varnode.
	 */
	public void emitPopCat1Value(String destName) {
		Varnode out = findVarnode(destName, 4);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
		in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(4, spVarnode.getSize());
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}

	/**
	 * Emits pcode to assign four bytes resulting from a call to a black-box pcodeop
	 * @param varnodeName - varnode name for holding result
	 * @param size - the size of the result
	 * @param pcodeop - name of pcodeop
	 * @param args - zero or more arguments for the pcodeop
	 */
	public void emitAssignVarnodeFromPcodeOpCall(String varnodeName, int size, String pcodeop,
			String... args) {
		Symbol useropSym = language.getSymbolTable().findGlobalSymbol(pcodeop);
		Varnode out = findVarnode(varnodeName, size);
		Varnode[] in;
		int opcode;
		if (useropSym instanceof UseropSymbol) {
			in = new Varnode[args.length + 1];
			in[0] = getConstant(((UseropSymbol) useropSym).getIndex(), 4);
			for (int i = 0; i < args.length; ++i) {
				in[i + 1] = constantOrRegister(args[i]);
			}
			opcode = PcodeOp.CALLOTHER;
		}
		else {
			in = new Varnode[args.length];
			for (int i = 0; i < args.length; ++i) {
				in[i] = constantOrRegister(args[i]);
			}
			opcode = findOpCode(pcodeop);
		}
		PcodeOp op = new PcodeOp(opAddress, seqnum++, opcode, in, out);
		opList.add(op);
	}

	/**
	 * Emits pcode to call a void black-box pcodeop
	 * @param pcodeop - name of pcodeop
	 * @param args - zero or more arguments for the pcodeop
	 */
	public void emitVoidPcodeOpCall(String pcodeop, String... args) {
		Symbol useropSym = language.getSymbolTable().findGlobalSymbol(pcodeop);
		Varnode[] in = new Varnode[args.length + 1];
		in[0] = getConstant(((UseropSymbol) useropSym).getIndex(), 4);
		for (int i = 0; i < args.length; ++i) {
			in[i + 1] = constantOrRegister(args[i]);
		}
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.CALLOTHER, in);
		opList.add(op);
	}

	/**
	 * Appends the pcode to assign an integer constant to a register
	 * @param register
	 * @param constant
	 */
	public void emitAssignConstantToRegister(String register, int constant) {
		Varnode out = findRegister(register);
		Varnode[] in = new Varnode[1];
		in[0] = getConstant(constant, out.getSize());
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, in, out);
		opList.add(op);
	}

	/**
	 * Appends the pcode to assign a register to the result of a pcode op call with arguments args
	 * @param register
	 * @param pcodeop
	 * @param args
	 */
	public void emitAssignRegisterFromPcodeOpCall(String register,
			String pcodeop, String... args) {
		Symbol useropSym = language.getSymbolTable().findGlobalSymbol(pcodeop);
		Varnode out = findRegister(register);
		Varnode[] in;
		int opcode;
		if (useropSym instanceof UseropSymbol) {
			in = new Varnode[args.length + 1];
			in[0] = getConstant(((UseropSymbol) useropSym).getIndex(), 4);
			for (int i = 0; i < args.length; ++i) {
				in[i + 1] = constantOrRegister(args[i]);
			}
			opcode = PcodeOp.CALLOTHER;
		}
		else {
			in = new Varnode[args.length];
			for (int i = 0; i < args.length; ++i) {
				in[i] = constantOrRegister(args[i]);
			}
			opcode = findOpCode(pcodeop);
		}
		PcodeOp op = new PcodeOp(opAddress, seqnum++, opcode, in, out);
		opList.add(op);
	}

	/**
	 * Appends the pcode to write to a value at an offset of a memory space
	 * @param space name of space
	 * @param size size of write
	 * @param offset offset in space
	 * @param value value to write
	 */
//	public void emitWriteToMemory(String space, int size, String offset, String value) {
//		Varnode[] in = new Varnode[3];
//		AddressSpace spc = language.getAddressFactory().getAddressSpace(space);
//		in[0] = getConstant(spc.getSpaceID(), 4);
//		if (offset.charAt(0) <= '9') {
//			String[] piece = offset.split(":");
//			int sz = Integer.parseInt(piece[1]);
//			long val = Long.decode(piece[0]);
//			in[1] = getConstant(val, sz);
//		}
//		else {
//			in[1] = findRegister(offset);
//		}
//		in[2] = findVarnode(value, size);
//		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.STORE, in);
//		opList.add(op);
//	}

	/**
	 * Appends the pcode to emit an indirect call
	 * @param target varnode to call indirectly
	 */
	public void emitIndirectCall(String target) {
		Varnode[] in = new Varnode[1];
		in[0] = findRegister(target);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.CALLIND, in);
		opList.add(op);
	}

	/**
	 * Appends the pcode to sign-extend the value src into dest
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public void emitSignExtension(String dest, int size, String src) {
		Varnode out = findVarnode(dest, size);
		Varnode[] in = new Varnode[1];
		in[0] = findRegister(src);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SEXT, in, out);
		opList.add(op);
	}

	/**
	 * Appends the pcode to zero-extend the value src into dest
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public void emitZeroExtension(String dest, int size, String src) {
		Varnode out = findVarnode(dest, size);
		Varnode[] in = new Varnode[1];
		in[0] = findRegister(src);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ZEXT, in, out);
		opList.add(op);
	}

	/**
	 * Appends the pcode truncate src into dest
	 * @param dest target varnode
	 * @param size size of target varnode
	 * @param src size of source varnode
	 */
	public void emitTruncate(String dest, int size, String src) {
		Varnode out = findVarnode(dest, size);
		Varnode[] in = new Varnode[2];
		in[0] = findRegister(src);
		in[1] = getConstant(0, 4);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.SUBPIECE, in, out);
		opList.add(op);
	}

	/**
	 * Appends the pcode to assign a varnode from a dereference of another varnode
	 * @param lhs target varnode
	 * @param size size of pointed-to value
	 * @param rhs varnode to dereference
	 */
	public void emitAssignVarnodeFromDereference(String lhs, int size, String rhs) {
		Varnode out = findVarnode(lhs, size);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = findRegister(rhs);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
	}

	private boolean compareVarnode(Varnode vn1, Varnode vn2, V8_PcodeOpEmitter op2) {
		if (vn1 == null) {
			return (vn2 == null);
		}
		if (vn2 == null) {
			return false;
		}
		if (vn1.getSize() != vn2.getSize()) {
			return false;
		}
		AddressSpace spc1 = vn1.getAddress().getAddressSpace();
		AddressSpace spc2 = vn2.getAddress().getAddressSpace();
		if (spc1 != spc2) {
			return false;
		}
		long offset1 = vn1.getOffset();
		long offset2 = vn2.getOffset();
		if (offset1 == offset2) {
			return true;
		}
		String name1 = findTempName(vn1.getAddress());
		if (name1 == null) {
			return false;
		}
		String name2 = op2.findTempName(vn2.getAddress());
		if (name2 == null) {
			return false;
		}
		return name1.equals(name2);
	}

	@Override
	public boolean equals(Object obj) {
		V8_PcodeOpEmitter op2 = (V8_PcodeOpEmitter) obj;
		if (opList.size() != op2.opList.size()) {
			return false;
		}
		for (int i = 0; i < opList.size(); ++i) {
			PcodeOp aop = opList.get(i);
			PcodeOp bop = op2.opList.get(i);
			if (aop.getOpcode() != bop.getOpcode()) {
				return false;
			}
			if (aop.getNumInputs() != bop.getNumInputs()) {
				return false;
			}
			if (!compareVarnode(aop.getOutput(), bop.getOutput(), op2)) {
				return false;
			}
			for (int j = 0; j < aop.getNumInputs(); ++j) {
				if (!compareVarnode(aop.getInput(j), bop.getInput(j), op2)) {
					return false;
				}
			}
		}
		return true;
	}
	
	public void emitAssignVarnodeFromVarnode(String varnodeOutName, String varnodeInName, int size) {
		Varnode out = findVarnode(varnodeOutName, size);
		Varnode[] in = new Varnode[1];
		in[0] = findVarnode(varnodeInName, size);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, in, out);
		opList.add(op);
	}
	
	public void emitVarnodeCall(String target, int size) {
		Varnode[] in = new Varnode[1];
		in[0] = findVarnode(target, size);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.CALLIND, in);
		opList.add(op);
	}
	public void emitConditionalBranchVarnode(Address instructionAddr, int condition, int size, String registerName) {
		//check condition
		PcodeOp op = null;
		Varnode compareRes = findVarnode("tmp_comp_out", size);
		Varnode[] in = new Varnode[2];
		in[0] = accVarnode;
		in[1] = findRegister(registerName);
		if (condition == 1) {
			op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_EQUAL, in, compareRes);
		}
		else {
			op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_NOTEQUAL, in, compareRes);
		}
		opList.add(op);
		in = new Varnode[2];
		//inputs
		in[1] = compareRes;
		in[0] = new Varnode(instructionAddr, size);
		// go!
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.CBRANCH, in);
		opList.add(op);
	}
}

