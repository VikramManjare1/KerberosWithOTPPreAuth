package kpa;

import java.io.Serializable;

public class KRB_402_AP_REP implements Serializable {
	private String msgCode, clientDataEncryptedEncoded;

	public KRB_402_AP_REP(String msgCode, String clientDataEncryptedEncoded) {
		this.msgCode = msgCode;
		this.clientDataEncryptedEncoded = clientDataEncryptedEncoded;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public String getClientDataEncryptedEncoded() {
		return clientDataEncryptedEncoded;
	}
	
	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += clientDataEncryptedEncoded;
		return result;
	}
}
