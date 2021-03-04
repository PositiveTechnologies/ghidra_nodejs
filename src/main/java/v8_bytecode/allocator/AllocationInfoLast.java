package v8_bytecode.allocator;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class AllocationInfoLast {
	private long lastAddr = 0L;
	private final MemoryBlock block;
	
	public AllocationInfoLast(final MemoryBlock block) {
		this.block = block;
	}
	
	public MemoryBlock getBlock() {
		return block;
	}
	
	public Address getAllocAddress(long newAddr) {
		lastAddr = newAddr;
		return block.getStart().add(newAddr);
	}
	
	public Address getAllocAddress() {
		return block.getStart().add(lastAddr);
	}
	
	public void setLastAddress(long lastAddr) {
		this.lastAddr = lastAddr;
	}
	
	public long getLastAddress() {
		return lastAddr;
	}
	
	public void incLastAddress(int size) {
		this.lastAddr += size;
	}
}
