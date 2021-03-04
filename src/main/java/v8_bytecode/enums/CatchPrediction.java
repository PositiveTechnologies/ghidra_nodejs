package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class CatchPrediction extends EnumDataType {

	public CatchPrediction() {
		super("CatchPrediction", 4);
		
		add("UNCAUGHT", 0);
		add("CAUGHT", 1);
		add("PROMISE", 2);
		add("DESUGARING", 3);
		add("ASYNC_AWAIT", 4);
	}

}
