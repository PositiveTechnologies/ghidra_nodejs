package v8_bytecode.storage;

import java.io.Serializable;

public final class ConstantPoolItemStore implements Serializable {
	private final Object item;
	private final long address;
	
	public ConstantPoolItemStore(final Object item, long address) {
		this.item = item;
		this.address = address;
	}

	public Object getItem() {
		return item;
	}

	public long getAddress() {
		return address;
	}
}
