package v8_bytecode;

import java.io.Serializable;
import java.util.Objects;


public final class HandlerTableEntry implements Serializable {
	private final int start;
	private final int end;
	private final int pred;
	private final int handler;
	private final int data;
	
	public HandlerTableEntry(int start, int end, int pred, int handler, int data) {
		this.start = start;
		this.end = end;
		this.pred = pred;
		this.handler = handler;
		this.data = data;
	}
	
	public int getStart() {
		return start;
	}
	
	public int getEnd() {
		return end;
	}
	
	public int getPrediction() {
		return pred;
	}
	
	public int getHandlerOffset() {
		return handler;
	}
	
	public int getData() {
		return data;
	}

	@Override
	public int hashCode() {
		return Objects.hash(data, end, handler, pred, start);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		HandlerTableEntry other = (HandlerTableEntry) obj;
		return data == other.data && end == other.end && handler == other.handler && pred == other.pred
				&& start == other.start;
	}
}
