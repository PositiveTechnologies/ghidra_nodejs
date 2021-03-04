package v8_bytecode.allocator;

import ghidra.program.model.address.Address;

public interface IObjectAllocator {
	public Address allocateNew(final IAllocatable obj, int size) throws Exception;
	public Address allocate(final Object data) throws Exception;
}
