package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;
import v8_bytecode.storage.RuntimesIntrinsicsStore;

public final class RuntimesEnum extends EnumDataType {
	
	public static final String NAME = "RUNTIME";
	
	public RuntimesEnum(final RuntimesIntrinsicsStore store) {
		super(NAME, 4);
		
		for (int i = 0; i < store.getNamesCount(); ++i) {
			final String funcName = store.getRuntimeName(i);
			add(funcName, i);
		}
	}
}
