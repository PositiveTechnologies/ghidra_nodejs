package v8_bytecode.allocator;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

public interface IAllocatable extends StructConverter {
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception;
}
