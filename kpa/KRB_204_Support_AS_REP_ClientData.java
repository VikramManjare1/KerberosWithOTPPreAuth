package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Hex;

public class KRB_204_Support_AS_REP_ClientData {
	private SecretKey sessionKey;
	private KRB_201_Support_Times times;
	private String nonce1, realm, tgsID;

	public KRB_204_Support_AS_REP_ClientData(SecretKey sessionKey, KRB_201_Support_Times times, String nonce1, String realm, String tgsID) {
		this.sessionKey = sessionKey;
		this.times = times;
		this.nonce1 = nonce1;
		this.realm = realm;
		this.tgsID = tgsID;
	}

	public SecretKey getSessionKey() {
		return sessionKey;
	}

	public KRB_201_Support_Times getTimes() {
		return times;
	}

	public String getNonce1() {
		return nonce1;
	}

	public String getRealm() {
		return realm;
	}

	public String getTgsID() {
		return tgsID;
	}

	public String toString() {
		String result = Shared.bytesToBase64(sessionKey.getEncoded()) + Shared.delimiter;
		result += times + Shared.delimiter;
		result += nonce1 + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += tgsID;
		return result;
	}

	public String getEncodedEncryptedTicketData(String keyTitle, SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("AS_REP ClientData",keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
