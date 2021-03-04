package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;


public class V8_InjectConstruct extends V8_InjectPayload {

	public V8_InjectConstruct(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
	}

	@Override
	public String getName() {
		return "ConstructCallOther";
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase); 	
		Symbol useropSym = language.getSymbolTable().findGlobalSymbol("Construct");
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		Integer opIndex = 2;
		Object[] opObjects = instruction.getOpObjects(opIndex);
		String[] args = new String[opObjects.length + 1];
		args[0] = instruction.getRegister(0).toString();
		for(int i=0; i < opObjects.length; i++) {
			args[i+1] = ((Register)opObjects[i]).toString();
		}
		pCode.emitAssignVarnodeFromPcodeOpCall("acc", 4, "Construct", args);
		return pCode.getPcodeOps();
	}

}
