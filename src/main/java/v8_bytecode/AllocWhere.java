package v8_bytecode;

public enum AllocWhere {
	kNewObject(0x00),
	kBackref(0x08),
	kBackrefWithSkip(0x10),
	kRootArray(0x05),
	kPartialSnapshotCache(0x06),
	kExternalReference(0x07),
	kAttachedReference(0x0D),
	kBuiltin(0x0E);
	
	private int value;
	
	AllocWhere(int value) {
		this.value = value;
	}
	
	public int getValue() {
		return value;
	}
}
