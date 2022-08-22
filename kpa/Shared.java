package kpa;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Hex;

public class Shared {
	public static final String AlgorithmAES = "AES";
	public static final int AlgorithmKeySizeBits256 = 256;
	public static final String transformation = "AES/ECB/PKCS5Padding";
	
	public static final String KDCIP = "localhost";
	public static final int ASPortNumber = 3001;
	public static final int TGSPortNumber = 3002;
	public static final int APPortNumber = 3003;

	public static final String TGSID = "TGS1";
	public static final String APID = "AP1";

	public static final String delimiter = ":column:";

	public static final String REALM = "KPA.COM";

	public static final String KRB_AS_REQ = "201";
	public static final String KRB_AS_ERR_PREAUTH_REQ = "202";
	public static final String KRB_AS_REQ_WITH_OTP = "203";
	public static final String KRB_AS_REP = "204";
	public static final String KRB_TGS_REQ = "301";
	public static final String KRB_TGS_REP = "302";
	public static final String KRB_AP_REQ = "401";
	public static final String KRB_AP_REP = "402";
	
	public static void waitForKey() throws IOException {
		System.out.println("Press Enter to continue...");
		System.in.read();
	}
	
	public static void checkMsgCode(String msgCode, String expectedMsgCode) {
		if (!msgCode.equals(expectedMsgCode)) {
			System.out.println(String.format("Unexpected message! Expecting %s message but received %s",
					expectedMsgCode, msgCode));
			System.exit(1);
		}
	}
	
	public static void checkRealm(String realm) {
		if (!realm.equals(REALM)) {
			System.out.println(
					String.format("Unexpected realm! Expecting %s realm but received %s", REALM, realm));
			System.exit(1);
		}
	}

	public static void sendObject(String title, ObjectOutputStream objectOutputStream, Object outputObject)
			throws IOException {
		if (outputObject != null) {
			System.out.println(String.format("\n%s:\n%s\n", title, outputObject));
			objectOutputStream.writeObject(outputObject);
		}
	}

	public static String bytesToBase64(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	public static byte[] base64ToBytes(String data) {
		return Base64.getDecoder().decode(data);
	}

	public static String readFile(String fileName) throws IOException {
		// Assumes only one line in file
		return new String(Files.readAllBytes(Paths.get(fileName)));
	}

	public static void writeFile(String fileName, String data) throws IOException {
		Files.write(Paths.get(fileName), data.getBytes());
		// Files.write(file, data, StandardOpenOption.APPEND);
	}

	public static void printKeysDatabase(Map<String, SecretKey> db) {
		System.out.println(String.format("%-10s\tKey", "ID"));
		for (String ID : db.keySet()) {
			System.out.println(
					String.format("%-10s\t%s", ID, String.format("%s", Hex.encodeHexString(db.get(ID).getEncoded()))));
		}
		Display.printDashedLine();
	}
}
