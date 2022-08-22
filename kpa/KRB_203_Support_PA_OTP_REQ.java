package kpa;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class KRB_203_Support_PA_OTP_REQ implements Serializable {
	private String nonce;
	private String otp;

	public KRB_203_Support_PA_OTP_REQ(String nonce, String otp) {
		this.nonce = nonce;
		this.otp = otp;
	}

	public String getNonce() {
		return nonce;
	}

	public String getOTP() {
		return otp;
	}

	public String toString() {
		String result = nonce + Shared.delimiter;
		result += otp;
		return result;
	}

	public String getPAOTPRequestEncryptedEncoded(String keyTitle, SecretKey key)
			throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		String plainText = this.toString();
		String cipherText = SKC.encrypt("PA_OTP_REQ", keyTitle, Shared.transformation, plainText, key);
		return cipherText;
	}
}
