package kpa;

import java.io.Serializable;

public class KRB_202_Support_PA_OTP_CHALLENGE implements Serializable {
	private String nonce;
	private int otpSizeBits, iterationCount;
	private String seed;

	public KRB_202_Support_PA_OTP_CHALLENGE(String nonce, int otpSizeBits, int iterationCount, String seed) {
		this.nonce = nonce;
		this.otpSizeBits = otpSizeBits;
		this.iterationCount = iterationCount;
		this.seed = seed;
	}

	public String getNonce() {
		return nonce;
	}

	public String getSeed() {
		return seed;
	}

	public int getOtpSizeBits() {
		return otpSizeBits;
	}

	public int getIterationCount() {
		return iterationCount;
	}
	
	public String toString() {
		String result = nonce + Shared.delimiter;
		result += otpSizeBits + Shared.delimiter;
		result += iterationCount + Shared.delimiter;
		result += seed;
		return result;
	}
}
