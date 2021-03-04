package v8_bytecode.enums;

import java.util.List;

import ghidra.program.model.data.EnumDataType;

public final class BuiltinsEnum extends EnumDataType {
	public BuiltinsEnum(final List<String> builtins) {
		super("BUILTINS", 4);
		
		for (final String builtin : builtins) {
			add(builtin, this.getCount());
		}
	}

	public int fromString(final String enName) {
		for (final String en : this.getNames()) {
			if (enName.equals(en)) {
				return (int) this.getValue(en);
			}
		}
		
		return -1;
	}
}
