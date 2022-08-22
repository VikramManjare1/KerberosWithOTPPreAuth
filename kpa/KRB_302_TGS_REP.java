package kpa;

import java.io.Serializable;

public class KRB_302_TGS_REP implements Serializable {
	private String msgCode, realm, clientID, apTicketEncryptedEncodedData, clientDataEncryptedEncoded;
	
	public KRB_302_TGS_REP(String msgCode, String realm, String clientID, String apTicketEncryptedEncodedData,
			String clientDataEncryptedEncoded) {
		this.msgCode = msgCode;
		this.realm = realm;
		this.clientID = clientID;
		this.apTicketEncryptedEncodedData = apTicketEncryptedEncodedData;
		this.clientDataEncryptedEncoded = clientDataEncryptedEncoded;
	}

	public String getMsgCode() {
		return msgCode;
	}

	public String getRealm() {
		return realm;
	}

	public String getClientID() {
		return clientID;
	}

	public String getApTicketEncryptedEncodedData() {
		return apTicketEncryptedEncodedData;
	}

	public String getClientDataEncryptedEncoded() {
		return clientDataEncryptedEncoded;
	}
	
	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += clientID + Shared.delimiter;
		result += apTicketEncryptedEncodedData + Shared.delimiter;
		result += clientDataEncryptedEncoded;
		return result;
	}
}
