package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class ScriptTypeEnum extends EnumDataType {

	public static enum ScriptType {
		NATIVE(0),
		EXTENSION(1),
		NORMAL(2),
		WASM(3),
		INSPECTOR(4);
		
		private final int value;
		
		ScriptType(int value) {
			this.value = value;
		}
		
		public static ScriptType fromInt(int value) {
			for (ScriptType type : values()) {
				if (type.value == value) {
					return type;
				}
			}
			
			return null;
		}
	}
	
	public ScriptTypeEnum() {
		super("SCRIPT_TYPE", 4);
		
		for (ScriptType type : ScriptType.values()) {
			add(type.name(), type.value);
		}
	}
}
