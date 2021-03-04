package v8_bytecode.storage;

import java.io.Serializable;

public final class ContextVarStore implements Serializable {

	private final long address;
	private final String name;

	public ContextVarStore(long address, final String name) {
		this.address = address;
		this.name = name;
	}
	
	public long getAddress() {
		return address;
	}

	public String getName() {
		return name;
	}
}
