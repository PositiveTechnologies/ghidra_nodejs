package v8_bytecode;

public enum AllocPoint {
	kStartOfObject(0x00),
	kInnerPointer(0x40);
	
	private final int value;
	
	AllocPoint(int value) {
		this.value = value;
	}
	
	public int getValue() {
		return value;
	}
}
