package v8_bytecode.enums;

public enum ScopeInfoFlagsLang {
	SLOPPY(0),
	STRICT(1);
	
	private final int value;
	
	ScopeInfoFlagsLang(int value) {
		this.value = value;
	}
	
	public static ScopeInfoFlagsLang fromInt(int value) {
		for (ScopeInfoFlagsLang lang : values()) {
			if (lang.value == value) {
				return lang;
			}
		}
		
		return null;
	}
}
