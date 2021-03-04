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

public final class ScopeInfoReceiver implements IAllocatable {

	private final int funcIndex;
	private final int flags;
	private final String name;
	
	private final Structure s;
	private ScopesInfoAllocator siAllocator;
	
	public ScopeInfoReceiver(int flags, final String name, final String type, int funcIndex, final ObjectsAllocator allocator) {
		allocator.getMonitor().setMessage(String.format("Creating ScopeInfoReceiver for function #%d", funcIndex));
		
		this.funcIndex = funcIndex;
		this.flags = flags;
		this.name = name;
		
		s = new StructureDataType(String.format("ScopeInfoFunc%s%d", type, funcIndex), 0);
		
		s.add(DWordDataType.dataType, -1, "Flags", null);
		
		if (name != null) {
			s.add(new PointerDataType(CharDataType.dataType), -1, "Name", null);
		}
	}
	
	public void setAllocator(final ScopesInfoAllocator siAllocator) {
		this.siAllocator = siAllocator;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = siAllocator.allocate(flags);
		
		if (name != null) {
			siAllocator.allocate(allocator.allocateInStrings(name));
		}
		
		return result;
	}

	@Override
	public int hashCode() {
		return Objects.hash(funcIndex);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ScopeInfoReceiver other = (ScopeInfoReceiver) obj;
		return funcIndex == other.funcIndex;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
