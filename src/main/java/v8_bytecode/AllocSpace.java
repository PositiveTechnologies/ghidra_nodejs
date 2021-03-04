package v8_bytecode;

public enum AllocSpace {
	NEW_SPACE(0x00),
	OLD_SPACE(0x01),
	CODE_SPACE(0x02),
	MAP_SPACE(0x03),
	LO_SPACE(0x04);
	
	private final int value;
	
	AllocSpace(int value) {
		this.value = value;
	}
	
	public static AllocSpace fromInt(int value) {
		for (AllocSpace space : values()) {
			if (space.value == value) {
				return space;
			}
		}
		
		return null;
	}
	
	public int getValue() {
		return value;
	}
}
