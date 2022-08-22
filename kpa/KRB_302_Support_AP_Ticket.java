package kpa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class KRB_302_Support_AP_Ticket {
	private SecretKey sessionKey;
	private String realm, clientID, clientAddress;
	private KRB_201_Support_Times times;
	
	public KRB_302_Support_AP_Ticket(SecretKey sessionKey, String realm, String clientID, String clientAddress, KRB_201_Support_Times times) {
		this.sessionKey = sessionKey;
		this.realm = realm;
		this.clientID = clientID;
		this.clientAddress = clientAddress;
		this.times = times;
	}

	public SecretKey getSessionKey() {
		return sessionKey;
	}

	public String getRealm() {
		return realm;
	}

	public String getClientID() {
		return clientID;
	}

	public String getClientAddress() {
		return clientAddress;
	}

	public KRB_201_Support_Times getTimes() {
		return times;
	}
	
	public String toString() {
		String result = Shared.bytesToBase64(sessionKey.getEncoded()) + Shared.delimiter;
		result += realm + Shared.delimiter;
		result += clientID + Shared.delimiter;
		result += clientAddress + Shared.delimiter;
		result += times;
		return result;
	}
	
	public String getEncodedEncryptedTicketData(String keyTitle, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("APTicket", keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
