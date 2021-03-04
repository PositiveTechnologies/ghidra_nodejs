package v8_bytecode.enums;

import ghidra.program.model.data.Enum;

public final class EnumDataTypes {
	private final Enum rootsEnum;
	private final Enum runsEnum;
	private final Enum intrsEnum;
	private final Enum jsRunsEnum;
	private final Enum builtins;
	private final Enum spt;
	private final Enum predict;
	private final Enum typeof;
	
	public EnumDataTypes(
			final Enum rootsEnum,
			final Enum runsEnum,
			final Enum intrsEnum,
			final Enum jsRunsEnum,
			final Enum builtins,
			final Enum spt,
			final Enum predict,
			final Enum typeof) {
		this.rootsEnum = rootsEnum;
		this.runsEnum = runsEnum;
		this.intrsEnum = intrsEnum;
		this.jsRunsEnum = jsRunsEnum;
		this.builtins = builtins;
		this.spt = spt;
		this.predict = predict;
		this.typeof = typeof;
	}
	
	public Enum getRoots() {
		return rootsEnum;
	}
	
	public Enum getRuntimesEnum() {
		return runsEnum;
	}
	
	public Enum getIntrinsicsEnum() {
		return intrsEnum;
	}
	
	public Enum getJsRuntimesEnum() {
		return jsRunsEnum;
	}
	
	public Enum getBuiltins() {
		return builtins;
	}
	
	public Enum getSpt() {
		return spt;
	}
	
	public Enum getCatchPrediction() {
		return predict;
	}
	
	public Enum getTypeOf() {
		return typeof;
	}
}
