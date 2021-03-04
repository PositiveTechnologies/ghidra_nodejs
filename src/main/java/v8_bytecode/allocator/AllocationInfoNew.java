package v8_bytecode.allocator;

public final class AllocationInfoNew {
	private long newAddr = 0L;
	
	public long getNewAddress() {
		return newAddr;
	}
	
	public void incNewAddress(int size) {
		newAddr += size;
	}
}
