package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class KRB_301_Support_TGS_REQ_Authenticator1 {
	private String clientID, realm, ts1;

	public KRB_301_Support_TGS_REQ_Authenticator1(String clientID, String realm, String ts1) {
		this.clientID = clientID;
		this.realm = realm;
		this.ts1 = ts1;
	}

	public String getClientID() {
		return clientID;
	}

	public String getRealm() {
		return realm;
	}

	public String getTs1() {
		return ts1;
	}

	public String toString() {
		String result = clientID + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += ts1;
		return result;
	}

	public String getEncodedEncryptedTicketData(String keyTitle, SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("TGS_REQ Authenticator1", keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
