package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KRB_401_Support_AP_REQ_Authenticator2 {
	private String clientID, realm, ts2;
	
	public KRB_401_Support_AP_REQ_Authenticator2(String clientID, String realm, String ts2) {
		this.clientID = clientID;
		this.realm = realm;
		this.ts2 = ts2;
	}

	public String getClientID() {
		return clientID;
	}

	public String getRealm() {
		return realm;
	}

	public String getTs2() {
		return ts2;
	}
	
	public String toString() {
		String result = clientID + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += ts2;
		return result;
	}
	
	public String getEncodedEncryptedTicketData(String keyTitle, SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("AP_REQ Authenticator2", keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
