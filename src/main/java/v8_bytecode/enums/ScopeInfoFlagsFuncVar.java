package v8_bytecode.enums;

public enum ScopeInfoFlagsFuncVar {
	NONE(0),
	STACK(1),
	CONTEXT(2),
	UNUSED(3);
	
	private final int value;
	
	ScopeInfoFlagsFuncVar(int value) {
		this.value = value;
	}
	
	public static ScopeInfoFlagsFuncVar fromInt(int value) {
		for (ScopeInfoFlagsFuncVar var : values()) {
			if (var.value == value) {
				return var;
			}
		}
		
		return null;
	}
}
