package v8_bytecode;

public final class CaseState {
	private final AllocWhere where;
	private final AllocHow how;
	private final AllocPoint within;
	private final int value;
	
	public CaseState(int val, AllocWhere where, AllocHow how, AllocPoint within) {
		this.value = val;
		this.where = where;
		this.how = how;
		this.within = within;
	}

	public AllocWhere getWhere() {
		return where;
	}

	public AllocHow getHow() {
		return how;
	}

	public AllocPoint getWithin() {
		return within;
	}

	public int getValue() {
		return value;
	}
}
