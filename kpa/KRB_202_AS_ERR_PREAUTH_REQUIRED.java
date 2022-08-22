package kpa;

import java.io.Serializable;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

public class KRB_202_AS_ERR_PREAUTH_REQUIRED implements Serializable {
	private String msgCode;
	private SecretKey fastSessionKey;
	private KRB_202_Support_PA_OTP_CHALLENGE paOTPChallenge;
	
	public KRB_202_AS_ERR_PREAUTH_REQUIRED(SecretKey fastSessionKey, KRB_202_Support_PA_OTP_CHALLENGE paOTPChallenge) {
		this.msgCode = "202";
		this.fastSessionKey = fastSessionKey;
		this.paOTPChallenge = paOTPChallenge;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public SecretKey getFastSessionKey() {
		return fastSessionKey;
	}

	public KRB_202_Support_PA_OTP_CHALLENGE getPaOTPChallenge() {
		return paOTPChallenge;
	}
	
	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += Hex.encodeHexString(fastSessionKey.getEncoded())+ Shared.delimiter;
		result += paOTPChallenge;
		return result;
	}
}
