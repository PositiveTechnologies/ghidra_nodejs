package v8_bytecode.structs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.ReservObject;
import v8_bytecode.allocator.IAllocatable;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.allocator.SharedFunctionsAllocator;

public final class FeedbackMetadataStruct implements IAllocatable {
	
	private final ReservObject rObj;
	private final List<Integer> items;
	
	private final Structure s;
	private SharedFunctionsAllocator sfAllocator = null;
	
	public FeedbackMetadataStruct(final ReservObject obj, int funcIndex, final ObjectsAllocator allocator) throws Exception {
		rObj = obj;
		allocator.getMonitor().setMessage(String.format("Creating FeedbackMetadata for function #%d", funcIndex));
		
		s = new StructureDataType(String.format("FeedbackMetadata%d", funcIndex), 0);
		
		int[] items_ = (int[])allocator.convertReservObject(obj);
		items = new ArrayList<>();
		
		for (int i = 0; i < items_.length; ++i) {
			items.add(items_[i]);
			s.add(DWordDataType.dataType, -1, String.format("Item%d", i), null);
		}
	}
	
	public void setAllocator(final SharedFunctionsAllocator sfAllocator) {
		this.sfAllocator = sfAllocator;
	}
	
	@Override
	public Address allocate(final ObjectsAllocator allocator, final TaskMonitor monitor) throws Exception {
		monitor.setMessage(String.format("Allocating %s...", this.getClass().getSimpleName()));
		
		Address result = sfAllocator.allocate(items.get(0));

		for (int i = 1; i < items.size(); ++i) {
			sfAllocator.allocate(items.get(i));
		}
		
		return result;
	}

	@Override
	public int hashCode() {
		return Objects.hash(rObj);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		FeedbackMetadataStruct other = (FeedbackMetadataStruct) obj;
		return Objects.equals(rObj, other.rObj);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return s;
	}

}
