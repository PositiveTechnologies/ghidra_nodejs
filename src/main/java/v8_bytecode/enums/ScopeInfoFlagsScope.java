package v8_bytecode.enums;

public enum ScopeInfoFlagsScope {
	EVAL_SCOPE(0),
	FUNCTION_SCOPE(1),
	MODULE_SCOPE(2),
	SCRIPT_SCOPE(3),
	CATCH_SCOPE(4),
	BLOCK_SCOPE(5),
	WITH_SCOPE(6);
	
	private final int value;
	
	ScopeInfoFlagsScope(int value) {
		this.value = value;
	}
	
	public static ScopeInfoFlagsScope fromInt(int value) {
		for (ScopeInfoFlagsScope scope : values()) {
			if (scope.value == value) {
				return scope;
			}
		}
		
		return null;
	}
}
