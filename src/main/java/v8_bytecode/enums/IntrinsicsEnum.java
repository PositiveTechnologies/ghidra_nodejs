package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;
import v8_bytecode.storage.RuntimesIntrinsicsStore;

public final class IntrinsicsEnum extends EnumDataType {
	public static final String NAME = "INTRINSIC";
	
	public IntrinsicsEnum(final RuntimesIntrinsicsStore store) {
		super(NAME, 4);
		
		for (int i = 0; i < store.getIntrinsicsCount(); ++i) {
			add(store.getIntrinsicName(i), i);
		}
	}
}
