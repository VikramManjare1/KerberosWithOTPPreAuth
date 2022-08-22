package kpa;

import java.io.Serializable;

import javax.crypto.spec.IvParameterSpec;

public class KRB_204_AS_REP implements Serializable {
	private String msgCode, realm, clientID, tgsTicketEncryptedEncodedData, clientDataEncryptedEncoded;

	public KRB_204_AS_REP(String realm, String clientID, String tgsTicketEncryptedEncodedData,
			String clientDataEncryptedEncoded) {
		this.msgCode = "204";
		this.realm = realm;
		this.clientID = clientID;
		this.tgsTicketEncryptedEncodedData = tgsTicketEncryptedEncodedData;
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

	public String getTgsTicketEncryptedEncodedData() {
		return tgsTicketEncryptedEncodedData;
	}

	public String getClientDataEncryptedEncoded() {
		return clientDataEncryptedEncoded;
	}

	public String toString() {
		String result = msgCode + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += clientID + Shared.delimiter;
		result += tgsTicketEncryptedEncodedData + Shared.delimiter;
		result += clientDataEncryptedEncoded;
		return result;
	}
}
