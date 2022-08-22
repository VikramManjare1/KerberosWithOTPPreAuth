package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KRB_402_Support_AP_REP_ClientData {
	private String ts2;
	
	public KRB_402_Support_AP_REP_ClientData(String ts2) {
		this.ts2 = ts2;
	}

	public String getTs2() {
		return ts2;
	}
	
	public String toString() {
		String result = ts2;
		return result;
	}
	
	public String getEncodedEncryptedTicketData(String keyTitle,SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("AP_REP ClientData",keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
