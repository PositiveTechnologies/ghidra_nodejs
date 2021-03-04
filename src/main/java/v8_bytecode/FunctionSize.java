package v8_bytecode;

import java.io.Serializable;

public final class FunctionSize implements Serializable {
	private final long address;
	private final int size;
	
	public FunctionSize(long address, int size) {
		this.address = address;
		this.size = size;
	}
	
	public long getAddress() {
		return address;
	}
	
	public int getSize() {
		return size;
	}
}
