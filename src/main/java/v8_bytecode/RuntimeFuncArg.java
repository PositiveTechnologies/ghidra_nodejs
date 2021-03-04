package v8_bytecode;

import java.io.Serializable;

public final class RuntimeFuncArg implements Serializable {
	private final String name;
	private final String type;
	
	public RuntimeFuncArg(String name, String type) {
		this.name = name;
		this.type = type;
	}
	
	public String getName() {
		return name;
	}
	
	public String getType() {
		return type;
	}
}
