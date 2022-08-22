package kpa;

import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

import java.io.*;

public class E1_AS {
	private boolean generateKeysFlag;
	protected volatile Map<String, SecretKey> ASDatabase;

	public E1_AS(boolean generateKeyFlag) {
		this.generateKeysFlag = generateKeyFlag;
		ASDatabase = new HashMap<String, SecretKey>();

		Display.printDashedLine();
		System.out.println("Started AS Server...");
		Display.printDashedLine();
	}

	private void generateTGSKeys() throws NoSuchAlgorithmException, IOException {
		int numTGSServers = 1;
		if (generateKeysFlag) {
			System.out.println(String.format("Generating %d ASTGS Shared Keys...", numTGSServers));
		} else {
			System.out.println(String.format("Reading %d ASTGS Shared Keys...", numTGSServers));
		}
		for (int i = 1; i <= numTGSServers; i++) {
			String TGSID = String.format("TGS%s", i);
			SecretKey key;
			if (generateKeysFlag) {
				System.out.println();
				key = SKC.generateKey("AG-TGS", Shared.AlgorithmAES, Shared.AlgorithmKeySizeBits256);
				Shared.writeFile(String.format("Shared/AS%sKey.txt", TGSID), Shared.bytesToBase64(key.getEncoded()));
			} else {
				byte[] decodedKey = Shared.base64ToBytes(Shared.readFile(String.format("Shared/AS%sKey.txt", TGSID)));
				key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
			}
			ASDatabase.put(TGSID, key);
		}
		Display.printDashedLine();
	}

	private void generateClientKeys(int numClients) throws NoSuchAlgorithmException, IOException {
		if (generateKeysFlag) {
			System.out.println(String.format("Generating %d ASClient Shared Keys...", numClients));
		} else {
			System.out.println(String.format("Reading %d ASClient Shared Keys...", numClients));
		}
		for (int i = 1; i <= numClients; i++) {
			String clientID = String.format("C%s", i);
			SecretKey key;
			if (generateKeysFlag) {
				System.out.println();
				key = SKC.generateKey("AS-Client", Shared.AlgorithmAES, Shared.AlgorithmKeySizeBits256);
				Shared.writeFile(String.format("Shared/AS%sKey.txt", clientID), Shared.bytesToBase64(key.getEncoded()));
			} else {
				byte[] decodedKey = Shared
						.base64ToBytes(Shared.readFile(String.format("Shared/AS%sKey.txt", clientID)));
				key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
			}
			ASDatabase.put(clientID, key);
		}
		Display.printDashedLine();
	}

	private void createDatabase(int numClients) throws NoSuchAlgorithmException, IOException {
		generateTGSKeys();
		generateClientKeys(numClients);
		Shared.printKeysDatabase(ASDatabase);
	}

	private void startListening() {
		boolean listening = true;
		try (ServerSocket serverSocket = new ServerSocket(Shared.ASPortNumber)) {
			while (listening) {
				System.out.println(String.format("\nStarted listening on Socket: %s:%s",
						serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort()));
				Socket connectSocket = serverSocket.accept();
				new ASThread(this, connectSocket).start();
			}
		} catch (IOException e) {
			System.err.println("Could not listen on port " + Shared.ASPortNumber);
			System.exit(1);
		}
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		boolean generateKeys = false;
		E1_AS as = new E1_AS(generateKeys);

		int numClients = 2;
		as.createDatabase(numClients);

		as.startListening();
	}
}

class ASThread extends Thread {
	private Socket socket = null;
	private String remoteSocketAddress;
	private E1_AS as;

	private static final int WAITING_201 = 0;
	private static final int SENT_202 = 1;
	private static final int WAITING_203 = 2;
	private static final int SENT_204 = 3;
	private int currentState = WAITING_201;
	private String otpValueExpected, otpNonceSent;
	private SecretKey fastArmorKey;

	public ASThread(E1_AS as, Socket socket) {
		super("MultiClientServerThread");
		this.as = as;
		this.socket = socket;
		remoteSocketAddress = socket.getRemoteSocketAddress().toString();
		System.out.println(String.format("Client %s connected", remoteSocketAddress));
	}

	public void run() {
		try {
			InputStream inputStream = socket.getInputStream();
			ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
			OutputStream outputStream = socket.getOutputStream();
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

			Object inputObject = (KRB_201_AS_REQ) objectInputStream.readObject();
			if (inputObject != null) {
				Object outputObject = processInput(inputObject);
				Shared.waitForKey();
				Shared.sendObject("AS", objectOutputStream, outputObject);
			}

			inputObject = (KRB_203_AS_REQ_WITH_OTP) objectInputStream.readObject();
			if (inputObject != null) {
				Object outputObject = processInput(inputObject);
				Shared.sendObject("AS", objectOutputStream, outputObject);
			}
			Display.printDashedLine();

			socket.close();
			System.out.println(String.format("Client %s terminated", remoteSocketAddress.toString()));
		} catch (ClassNotFoundException | IOException | InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException
				| BadPaddingException | IllegalBlockSizeException e) {
			e.printStackTrace();
		}
	}

	public Object processInput(Object inputObject)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		Object theOutput = null;

		if (currentState == WAITING_201) {

			// Extract information from KRB_201_AS_REQ
			Display.printDashedLine();
			KRB_201_AS_REQ receivedObject = (KRB_201_AS_REQ) inputObject;

			String msgCode = receivedObject.getMsgCode();
			Shared.checkMsgCode(msgCode, Shared.KRB_AS_REQ);

			String realm = receivedObject.getRealm();
			Shared.checkRealm(realm);

			String clientID = receivedObject.getClientID();
			String tgsID = receivedObject.getTgsID();
			KRB_201_Support_Times times = receivedObject.getTimes();
			String nonce1 = receivedObject.getNonce1();

			System.out.println(String.format("Received %s msg from client %s:", msgCode, remoteSocketAddress));
			System.out.println(String.format("%-30s%s", "msgCode", msgCode));
			System.out.println(String.format("%-30s%s", "clientID", clientID));
			System.out.println(String.format("%-30s%s", "realm", realm));
			System.out.println(String.format("%-30s%s", "tgsID", tgsID));
			System.out.println(String.format("%-30s%s", "startTime",
					Instant.ofEpochMilli(times.getStartTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "endTime",
					Instant.ofEpochMilli(times.getEndTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "nonce1", nonce1));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Generate FAST Armor Session Key, PA_OTP_CHALLENGE and send
			// KRB_202_AS_ERR_PREAUTH_REQUIRED
			Display.printSolidLine();
			System.out.println("\nSending KRB_AS_ERR_PREAUTH_REQUIRED...");

			System.out.println("\nGenerating Session Key for FAST Armor...");
			SecretKey fastSessionKey = SKC.generateKey("FAST Armor Session", Shared.AlgorithmAES,
					Shared.AlgorithmKeySizeBits256);

			System.out.println("\nGenerating PA_OTP_CHALLENGE...");
			otpNonceSent = SKC.generateNonce();
			int otpSizeBits = 256;
			int otpIterationCount = 5;
			String otpSeed = SKC.generateNonce();
			KRB_202_Support_PA_OTP_CHALLENGE paOTPChallenge = new KRB_202_Support_PA_OTP_CHALLENGE(otpNonceSent,
					otpSizeBits, otpIterationCount, otpSeed);

			theOutput = new KRB_202_AS_ERR_PREAUTH_REQUIRED(fastSessionKey, paOTPChallenge);

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Generate FAST Armor Key
			Display.printSolidLine();
			System.out.println("Generating FAST Armor Key...");
			fastArmorKey = SKC.combineSecretKeys("FAST Armor", fastSessionKey, as.ASDatabase.get(clientID),
					Shared.AlgorithmAES);

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Generate Expected OTP Value
			Display.printSolidLine();
			System.out.println("Generating Expected OTP...");
			String preOTPStr = Hex.encodeHexString(as.ASDatabase.get(clientID).getEncoded()) + otpSeed;
			byte[] expectedOTPBytes = SKC.generateOTP(otpSizeBits, otpIterationCount, preOTPStr);
			otpValueExpected = Hex.encodeHexString(expectedOTPBytes);
			System.out.println(String.format("%db expected OTP: %s\n", expectedOTPBytes.length * 8, otpValueExpected));

			currentState = SENT_202;

		} else if (currentState == SENT_202 || currentState == WAITING_203) {

			// Extract information from KRB_203_AS_REQ_WITH_OTP
			Display.printDashedLine();
			KRB_203_AS_REQ_WITH_OTP receivedObject = (KRB_203_AS_REQ_WITH_OTP) inputObject;

			String msgCode = receivedObject.getMsgCode();
			Shared.checkMsgCode(msgCode, Shared.KRB_AS_REQ_WITH_OTP);

			String realm = receivedObject.getRealm();
			Shared.checkRealm(realm);

			String clientID = receivedObject.getClientID();
			String tgsID = receivedObject.getTgsID();
			KRB_201_Support_Times times = receivedObject.getTimes();
			String nonce1 = receivedObject.getNonce1();
			String paOTPRequestEncryptedEncoded = receivedObject.getPaOTPRequestEncryptedEncodedData();

			System.out.println(String.format("Received %s msg from client %s:", msgCode, remoteSocketAddress));
			System.out.println(String.format("%-30s%s", "msgCode", msgCode));
			System.out.println(String.format("%-30s%s", "clientID", clientID));
			System.out.println(String.format("%-30s%s", "realm", realm));
			System.out.println(String.format("%-30s%s", "tgsID", tgsID));
			System.out.println(String.format("%-30s%s", "startTime",
					Instant.ofEpochMilli(times.getStartTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "endTime",
					Instant.ofEpochMilli(times.getEndTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "nonce1", nonce1));
			System.out.println(String.format("%-30s%s\n", "Enc OTP Request", paOTPRequestEncryptedEncoded));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Decrypt encrypted paOTPRequest using fastArmorKey and verify Nonce + OTP
			// Value sent by client
			// If Nonce + OTP Value matches with expected Nonce + OTP Value,
			// Preauthentication is successful!
			String paOTPRequest = SKC.decrypt("paOTPRequest", "fastArmorKey", Shared.transformation,
					paOTPRequestEncryptedEncoded, fastArmorKey);
			String[] paOTPRequestSplit = paOTPRequest.split(Shared.delimiter);
			String otpNonceReceived = paOTPRequestSplit[0];
			if (!otpNonceReceived.equals(otpNonceSent)) {
				System.out.println(String.format("Unexpected otpNonce! Expecting %s otpNonce but received %s",
						otpNonceSent, otpNonceReceived));
				System.exit(1);
			}
			String otpValueReceived = paOTPRequestSplit[1];
			if (!otpValueReceived.equals(otpValueExpected)) {
				System.out.println(String.format("Unexpected otpValue! Expecting %s otpValue but received %s",
						otpValueExpected, otpValueReceived));
				System.exit(1);
			}
			System.out.println(String.format("%-30s%s", "otpNonceReceived", otpNonceReceived));
			System.out.println(String.format("%-30s%s", "otpValueReceived", otpValueReceived));
			System.out.println("otpValue matched! Preauthentication Successful!");

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Generate TGSTicket i.e. TGT, Session Key for TGS-Client Communication and send KRB_204_AS_REP
			Display.printSolidLine();
			System.out.println("Generating TGSTicket...");
			SecretKey tgsKey = as.ASDatabase.get(tgsID);
			SecretKey sessionKey = SKC.generateKey("TGS-Client Session", Shared.AlgorithmAES,
					Shared.AlgorithmKeySizeBits256);

			KRB_204_Support_TGS_Ticket tgsTicket = new KRB_204_Support_TGS_Ticket(sessionKey, realm, clientID,
					remoteSocketAddress.toString(), times);
			String tgsTicketEncryptedEncodedData = tgsTicket.getEncodedEncryptedTicketData("tgsKey", tgsKey);

			KRB_204_Support_AS_REP_ClientData clientData = new KRB_204_Support_AS_REP_ClientData(sessionKey, times,
					nonce1, realm, tgsID);
			String clientDataEncryptedEncodedData = clientData.getEncodedEncryptedTicketData("fastArmorKey",
					fastArmorKey);

			theOutput = new KRB_204_AS_REP(realm, clientID, tgsTicketEncryptedEncodedData,
					clientDataEncryptedEncodedData);
			currentState = SENT_204;

		} else {
			currentState = WAITING_201;
		}
		return theOutput;
	}
}
