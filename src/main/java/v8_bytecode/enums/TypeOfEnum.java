package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class TypeOfEnum extends EnumDataType {

	public static final String NAME = "TYPEOF";
	
	public TypeOfEnum() {
		super(NAME, 4);
		
		add("Number", 0);
		add("String", 1);
		add("Symbol", 2);
		add("Boolean", 3);
		add("Undefined", 4);
		add("Function", 5);
		add("Object", 6);
		add("Other", 7);
	}

}
