package v8_bytecode.enums;

import ghidra.program.model.data.EnumDataType;

public final class ScriptSourceEnum extends EnumDataType {

	public ScriptSourceEnum() {
		super("SCRIPT_SOURCE", 4);

		add("Source", 4);
	}

	public int fromString(final String ssName) {
		for (final String ss : this.getNames()) {
			if (ssName.equals(ss)) {
				return (int) this.getValue(ss);
			}
		}
		
		return -1;
	}
}
