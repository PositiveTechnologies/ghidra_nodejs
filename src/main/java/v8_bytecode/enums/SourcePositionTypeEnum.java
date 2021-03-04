package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class SourcePositionTypeEnum extends EnumDataType {
	public SourcePositionTypeEnum() {
		super("SRC_POS_TYPE", 4);
		
		add("EXPRESSION", 0);
		add("STATEMENT", 1);
	}
}
