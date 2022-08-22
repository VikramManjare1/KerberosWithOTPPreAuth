package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class KRB_302_Support_TGS_REP_ClientData {
	private SecretKey sessionKey;
	private KRB_201_Support_Times times;
	private String nonce2, realm, apID;
	
	public KRB_302_Support_TGS_REP_ClientData(SecretKey sessionKey, KRB_201_Support_Times times, String nonce2, String realm, String apID) {
		this.sessionKey = sessionKey;
		this.times = times;
		this.nonce2 = nonce2;
		this.realm = realm;
		this.apID = apID;
	}

	public SecretKey getSessionKey() {
		return sessionKey;
	}

	public KRB_201_Support_Times getTimes() {
		return times;
	}

	public String getNonce2() {
		return nonce2;
	}

	public String getRealm() {
		return realm;
	}

	public String getApID() {
		return apID;
	}
	
	public String toString() {
		String result = Shared.bytesToBase64(sessionKey.getEncoded()) + Shared.delimiter;
		result += times + Shared.delimiter;
		result += nonce2 + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += apID;
		return result;
	}
	
	public String getEncodedEncryptedTicketData(String keyTitle,SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("TGS_REP ClientData",keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
