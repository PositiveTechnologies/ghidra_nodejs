package v8_bytecode.storage;

import java.io.Serializable;
import java.util.List;

public final class ConstantPoolStore implements Serializable {

	private final List<ConstantPoolItemStore> items;
	
	public ConstantPoolStore(final List<ConstantPoolItemStore> items) {
		this.items = items;
	}
	
	public Object getConstItem(int index) {
		return items.get(index).getItem();
	}
	
	public long getConstItemAddress(int index) {
		return items.get(index).getAddress();
	}
}
