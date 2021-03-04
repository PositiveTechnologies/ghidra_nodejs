package v8_bytecode.structs;

import java.io.IOException;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.ScopesInfoAllocator;

public final class ContextVarStruct implements IAllocatable {

	private final Structure s;
	
	private final int flags;
	private final String name;

	private ScopesInfoAllocator siAllocator;
	
	private Address allocAddr = null;
	
	public ContextVarStruct(int flags, final String name, final ObjectsAllocator allocator) {
		allocator.getMonitor().setMessage("Creating ContextVar");
		
		s = new StructureDataType("ContextVar", 0);
		
		this.flags = flags;
		s.add(DWordDataType.dataType, -1, "Flags", null);
		
		this.name = name;
		s.add(new PointerDataType(CharDataType.dataType), -1, "Name", null);
		
		s.add(DWordDataType.dataType, -1, "Value", null); // to store a value and to point it
	}
	
	public void setAllocator(final ScopesInfoAllocator siAllocator) {
		this.siAllocator = siAllocator;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = siAllocator.allocate(flags);
		allocAddr = allocator.allocateInStrings(name);
		siAllocator.allocate(allocAddr);
		siAllocator.allocate(0); // allocating initial value
		
		return result;
	}
	
	public Address getAddress() {
		return allocAddr;
	}
	
	public String getName() {
		return name;
	}

	@Override
	public int hashCode() {
		return Objects.hash(flags, name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ContextVarStruct other = (ContextVarStruct) obj;
		return flags == other.flags && Objects.equals(name, other.name);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
