package v8_bytecode;

public enum AllocHow {
	kPlain(0x00),
	kFromCode(0x20);
	
	private final int value;
	
	AllocHow(int value) {
		this.value = value;
	}
	
	public int getValue() {
		return value;
	}
}
