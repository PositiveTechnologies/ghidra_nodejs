package v8_bytecode.enums;

import java.util.List;

import ghidra.program.model.data.EnumDataType;

public final class JsRuntimesEnum extends EnumDataType {
	public static final String NAME = "JSRUNTIME";
	
	public JsRuntimesEnum(final List<String> items) {
		super(NAME, 4);
		
		for (final String item : items) {
			add(item, this.getCount());
		}
	}
}
