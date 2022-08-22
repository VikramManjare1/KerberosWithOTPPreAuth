package kpa;

import java.io.Serializable;

public class KRB_203_AS_REQ_WITH_OTP implements Serializable {
	private String msgCode, clientID, realm, tgsID;
	private KRB_201_Support_Times times;
	private String nonce1, paOTPRequestEncryptedEncoded;
	
	public KRB_203_AS_REQ_WITH_OTP(String msgCode, String clientID, String realm, String tgsID, KRB_201_Support_Times times, String nonce1, String paOTPRequestEncryptedEncodedData) {
		this.msgCode = msgCode;
		this.clientID = clientID;
		this.realm = realm;
		this.tgsID = tgsID;
		this.times = times;
		this.nonce1 = nonce1;
		this.paOTPRequestEncryptedEncoded = paOTPRequestEncryptedEncodedData;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public String getClientID() {
		return clientID;
	}

	public String getRealm() {
		return realm;
	}

	public String getTgsID() {
		return tgsID;
	}

	public KRB_201_Support_Times getTimes() {
		return times;
	}

	public String getNonce1() {
		return nonce1;
	}

	public String getPaOTPRequestEncryptedEncodedData() {
		return paOTPRequestEncryptedEncoded;
	}

	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += clientID + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += tgsID + Shared.delimiter;
		result += times + Shared.delimiter;
		result += nonce1 + Shared.delimiter;
		result += paOTPRequestEncryptedEncoded;
		return result;
	}
}
