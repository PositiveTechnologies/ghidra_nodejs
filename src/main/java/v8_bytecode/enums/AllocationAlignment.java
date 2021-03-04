package v8_bytecode.enums;

public enum AllocationAlignment {
	kWordAligned(0),
	kDoubleAligned(1),
	kDoubleUnaligned(2);
	
	private final int value;
	
	private AllocationAlignment(int value) {
		this.value = value;
	}
	
	public static AllocationAlignment fromInt(int value) {
		for (final AllocationAlignment align : values()) {
			if (align.value == value) {
				return align;
			}
		}
		
		return null;
	}
}
