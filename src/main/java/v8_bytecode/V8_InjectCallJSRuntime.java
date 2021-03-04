package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class V8_InjectCallJSRuntime extends V8_InjectPayload {

	public V8_InjectCallJSRuntime(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
		// TODO Auto-generated constructor stub
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase); 
		Address opAddr = context.baseAddr;
		Integer callerParamsCount;
		Integer argIndex = 0;
		Integer callerArgIndex = 0;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		Object[] opObjects = instruction.getOpObjects(2);
		String[] args = new String[opObjects.length + 1];
		
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
		pCode.emitIndirectCall("acc");
		while (callerArgIndex > 0) {
			callerArgIndex--;
			pCode.emitPopCat1Value("a" + callerArgIndex);
		}
		return pCode.getPcodeOps();
	}

}
