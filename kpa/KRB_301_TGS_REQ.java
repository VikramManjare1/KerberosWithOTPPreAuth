package kpa;

import java.io.Serializable;

public class KRB_301_TGS_REQ implements Serializable {
	private String msgCode, apID;
	private KRB_201_Support_Times times;
	private String nonce2, tgsTicketEncryptedEncodedData, authenticator1EncryptedEncodedData;

	public KRB_301_TGS_REQ(String msgCode, String apID, KRB_201_Support_Times times, String nonce2,
			String tgsTicketEncryptedEncodedData, String authenticator1EncryptedEncodedData) {
		this.msgCode = msgCode;
		this.apID = apID;
		this.times = times;
		this.nonce2 = nonce2;
		this.tgsTicketEncryptedEncodedData = tgsTicketEncryptedEncodedData;
		this.authenticator1EncryptedEncodedData = authenticator1EncryptedEncodedData;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public String getApID() {
		return apID;
	}

	public KRB_201_Support_Times getTimes() {
		return times;
	}

	public String getNonce2() {
		return nonce2;
	}

	public String getTgsTicketEncryptedEncodedData() {
		return tgsTicketEncryptedEncodedData;
	}

	public String getAuthenticator1EncryptedEncodedData() {
		return authenticator1EncryptedEncodedData;
	}

	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += apID + Shared.delimiter;
		result += times + Shared.delimiter;
		result += nonce2 + Shared.delimiter;
		result += tgsTicketEncryptedEncodedData + Shared.delimiter;
		result += authenticator1EncryptedEncodedData;
		return result;
	}

}
