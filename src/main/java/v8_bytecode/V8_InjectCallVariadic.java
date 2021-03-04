package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;


public class V8_InjectCallVariadic extends V8_InjectPayload {

public V8_InjectCallVariadic(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
		// TODO Auto-generated constructor stub
	}

//	public V8_InjectInvokeIntrinsicCallRuntime(String sourceName, SleighLanguage language) {
//		super(sourceName, language);
//		// TODO Auto-generated constructor stub
//	}

	int INTRINSICTYPE = 1;
	int RUNTIMETYPE = 2;
	int PROPERTYTYPE = 3;
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Integer callerParamsCount;
		Integer argIndex = 0;
		Integer callerArgIndex = 0;
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase); 
		Address opAddr = context.baseAddr;
		
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		// get arguments from slaspec, definition in cspec
		Integer funcType = (int) context.inputlist.get(0).getOffset();
		Integer receiver = (int) context.inputlist.get(1).getOffset();
		// extract and convert runtime id if runtime/intrinsic function called
		if (funcType != PROPERTYTYPE) {
			Integer index = (int) instruction.getScalar(0).getValue();
			pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(), index.toString(), 
					funcType.toString());
		}
		else {
			pCode.emitAssignVarnodeFromVarnode("call_target", instruction.getRegister(0).toString(), 4);
		}
		// get register range
		Object[] tOpObjects = instruction.getOpObjects(2);
		// get caller args count to save only necessary ones
		// it does not match the logic of the node.exe but important for output quality
		Object[] opObjects;
		Register recvOp = null;
		if (receiver == 1) {
			recvOp = (Register)tOpObjects[0];
			opObjects = new Object[tOpObjects.length - 1];
			System.arraycopy(tOpObjects, 1, opObjects, 0, tOpObjects.length - 1);
		}
		else
		{
			opObjects = new Object[tOpObjects.length];
			System.arraycopy(tOpObjects, 0, opObjects, 0, tOpObjects.length);
		}
		try {
			callerParamsCount = program.getListing().getFunctionContaining(opAddr).getParameterCount();
		}
		catch(Exception e) {
			callerParamsCount = 0;
		}
		if (callerParamsCount >  opObjects.length) {
			callerParamsCount = opObjects.length;
		}	
		for (; callerArgIndex < callerParamsCount; callerArgIndex++) {
			pCode.emitPushCat1Value("a" + callerArgIndex);
		}
		// save instruction operands in locals
		argIndex = opObjects.length;
		for (Object o: opObjects) {
			argIndex--;
			Register currentOp = (Register)o;
			String invokeTmp = "invoke_tmp_" + "a" + argIndex;
			pCode.emitAssignVarnodeFromVarnode(invokeTmp, currentOp.toString(), 4);
		}
		// writing locals into aX registers to avoid mixing up arguments
		argIndex = opObjects.length;
		for (Object o: opObjects) {
			argIndex--;
			String invokeTmp = "invoke_tmp_" + "a" + argIndex;
			pCode.emitAssignVarnodeFromVarnode("a" + argIndex, invokeTmp, 4);
		}
		// make call
		pCode.emitVarnodeCall("call_target", 4);
		while (callerArgIndex > 0) {
			callerArgIndex--;
			pCode.emitPopCat1Value("a" + callerArgIndex);
		}
		if (receiver == 1) {
			pCode.emitAssignVarnodeFromVarnode(recvOp.toString(), "acc", 4);
		}
//		else if (receiver == 2) {
//		//	*:4 fixset_addr = ret2:4;
//		//  *:4 (fixset_addr+4) = ret2[4,8];
//		}
		

		return pCode.getPcodeOps();
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectCallVariadic";
	}

}
