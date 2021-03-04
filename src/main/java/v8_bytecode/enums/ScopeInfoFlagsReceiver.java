package v8_bytecode.enums;

public enum ScopeInfoFlagsReceiver {
	NONE(0),
	STACK(1),
	CONTEXT(2),
	UNUSED(3);
	
	private final int value;
	
	ScopeInfoFlagsReceiver(int value) {
		this.value = value;
	}
	
	public static ScopeInfoFlagsReceiver fromInt(int value) {
		for (ScopeInfoFlagsReceiver recv : values()) {
			if (recv.value == value) {
				return recv;
			}
		}
		
		return null;
	}
}
