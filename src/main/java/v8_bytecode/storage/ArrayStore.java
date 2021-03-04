package v8_bytecode.storage;

import java.io.Serializable;

import v8_bytecode.structs.ArrayStruct;

public final class ArrayStore implements Serializable {
	private final String name;
	
	private ArrayStore(final String name) {
		this.name = name;
	}

	public static ArrayStore fromStruct(final ArrayStruct struct) {
		return new ArrayStore(struct.getName());
	}
	
	public String getName() {
		return name;
	}
}
