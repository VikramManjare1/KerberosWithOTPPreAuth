package kpa;

import java.io.Serializable;

public class KRB_201_Support_Times implements Serializable  {
	private long startTime, endTime;
	
	public KRB_201_Support_Times(long startTime, long endTime) {
		this.startTime = startTime;
		this.endTime = endTime;
	}

	public long getStartTime() {
		return startTime;
	}

	public long getEndTime() {
		return endTime;
	}
	
	public String toString() {
		String result = startTime + Shared.delimiter;
		result += endTime;
		return result;
	} 
	
}
