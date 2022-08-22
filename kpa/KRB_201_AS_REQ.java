package kpa;

import java.io.Serializable;

public class KRB_201_AS_REQ implements Serializable {
	private String msgCode, clientID, realm, tgsID;
	private KRB_201_Support_Times times;
	private String nonce1;

	public KRB_201_AS_REQ(String msgCode, String clientID, String realm, String tgsID, KRB_201_Support_Times times, String nonce1) {
		this.msgCode = msgCode;
		this.clientID = clientID;
		this.realm = realm;
		this.tgsID = tgsID;
		this.times = times;
		this.nonce1 = nonce1;
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
	
	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += clientID + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += tgsID + Shared.delimiter;
		result += times + Shared.delimiter;
		result += nonce1;
		return result;
	}
}
