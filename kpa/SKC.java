package kpa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class SKC {
	public static final String PRF = "PBKDF2WithHmacSHA256";

	public static byte[] generateOTP(int otpSizeBits, int iterationCount, String preOTPStr)
			throws NoSuchAlgorithmException {
		byte[] OTPBytes = SKC.getSHA(preOTPStr, otpSizeBits);
		System.out.println(String.format("%db OTP SHA-%d %d times: %s\n", OTPBytes.length * 8, otpSizeBits, 1,
				Hex.encodeHexString(OTPBytes)));
		for (int i = 2; i <= iterationCount; i++) {
			OTPBytes = SKC.getSHA(Hex.encodeHexString(OTPBytes), otpSizeBits);
			System.out.println(String.format("%db OTP SHA-%d %d times: %s\n", OTPBytes.length * 8, otpSizeBits, i,
					Hex.encodeHexString(OTPBytes)));
		}
		return OTPBytes;
	}

	public static byte[] getSHA(String input, int hashBits) throws NoSuchAlgorithmException {
		String shaAlgorithm = "SHA-" + hashBits;
		MessageDigest md = MessageDigest.getInstance(shaAlgorithm);
		return md.digest(input.getBytes(StandardCharsets.UTF_8));
	}

	private static byte[] combineBytes(byte[] b1, byte[] b2) {
		byte[] combined = new byte[b1.length + b2.length];

		System.arraycopy(b1, 0, combined, 0, b1.length);
		System.arraycopy(b2, 0, combined, b1.length, b2.length);
		return combined;
	}

	public static SecretKey combineSecretKeys(String title, SecretKey key1, SecretKey key2, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
		byte[] key1Encoded = key1.getEncoded();
		byte[] key2Encoded = key2.getEncoded();
		byte[] combinedKeysHash = getSHA(Hex.encodeHexString(combineBytes(key1Encoded, key2Encoded)), 256);

		SecretKey secretKey = new SecretKeySpec(combinedKeysHash, 0, combinedKeysHash.length, algorithm);
		printKey(title, secretKey);
		return secretKey;
	}

	public static String generateNonce() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[8];
		random.nextBytes(bytes);
		Encoder encoder = Base64.getUrlEncoder().withoutPadding();
		String token = encoder.encodeToString(bytes);
		return token;
	}

	public static SecretKey generateKey(String title, String algorithm, int keySizeBits)
			throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(keySizeBits);
		SecretKey key = keyGenerator.generateKey();
		printKey(title, key);
		return key;
	}

	public static void printKey(String title, SecretKey key) {
		byte[] keyBytes = key.getEncoded();
		System.out.println(
				String.format("\n%db %s Key: %s\n", keyBytes.length * 8, title, Hex.encodeHexString(keyBytes)));
	}

	public static SecretKey getKeyFromPassword(String algorithm, int keySizeBits, String password, String salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(PRF);
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, keySizeBits);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), algorithm);
		return secret;
	}

	public static IvParameterSpec generateIv(int IVSizeBits) {
		byte[] iv = new byte[IVSizeBits / 8];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static String encrypt(String title, String keyTitle, String algorithm, String input, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		System.out.println(
				String.format("\n%s Encryption:\n%s Key: %s", title, keyTitle, Hex.encodeHexString(key.getEncoded())));
//		System.out.println(String.format("IV: %s\n", Hex.encodeHexString(iv.getIV())));

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(input.getBytes());
		return Base64.getEncoder().encodeToString(cipherText);
	}

	public static String decrypt(String title, String keyTitle, String algorithm, String cipherText, SecretKey key)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		System.out.println(
				String.format("\n%s Decryption:\n%s Key: %s\n", title, keyTitle, Hex.encodeHexString(key.getEncoded())));
//		System.out.println(String.format("IV: %s\n", Hex.encodeHexString(iv.getIV())));

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		return new String(plainText);
	}

	public static String encryptPasswordBased(String algorithm, String plainText, SecretKey key, IvParameterSpec iv)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
	}

	public static String decryptPasswordBased(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
	}

	// Driver code
	public static void main(String args[]) throws Exception {
		String plainText = "Hello World!";
		SecretKey key = generateKey("main", "AES", 256);

//		IvParameterSpec ivParameterSpec = generateIv(128);
//		System.out.println("128B Random IV: " + Hex.encodeHexString(ivParameterSpec.getIV()));

		String transformation = "AES/ECB/PKCS5Padding";
		String cipherText = encrypt("main", "random", transformation, plainText, key);
		System.out.println("The ciphertext or " + "Encrypted Message is: " + cipherText);

		String decryptedText = decrypt("main", "random", transformation, cipherText, key);
		System.out.println("Your original message is: " + decryptedText);

		String passPhrase = "OpenSSL";
		key = getKeyFromPassword("AES", 256, passPhrase, "randomSalt");
		System.out.println("256b Password Key: " + Hex.encodeHexString(key.getEncoded()));

		cipherText = encrypt("main2", "random", transformation, plainText, key);
		System.out.println("The ciphertext or " + "Encrypted Message is: " + cipherText);

		decryptedText = decrypt("main2", "random", transformation, cipherText, key);
		System.out.println("Your original message is: " + decryptedText);
	}
}
