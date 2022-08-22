package kpa;

import java.io.Serializable;

public class KRB_401_AP_REQ implements Serializable {
	private String msgCode;
	private String apTicketEncryptedEncodedData, authenticator2EncryptedEncodedData;

	public KRB_401_AP_REQ(String msgCode, String apTicketEncryptedEncodedData,
			String authenticator2EncryptedEncodedData) {
		this.msgCode = msgCode;
		this.apTicketEncryptedEncodedData = apTicketEncryptedEncodedData;
		this.authenticator2EncryptedEncodedData = authenticator2EncryptedEncodedData;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public String getApTicketEncryptedEncodedData() {
		return apTicketEncryptedEncodedData;
	}

	public String getAuthenticator2EncryptedEncodedData() {
		return authenticator2EncryptedEncodedData;
	}
	
	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += apTicketEncryptedEncodedData + Shared.delimiter;
		result += authenticator2EncryptedEncodedData;
		return result;
	}
}
