package kpa;

import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class E4_Client {
	private String myID;
	private Map<String, SecretKey> ClientDatabase;

	public E4_Client(String myID) throws IOException {
		this.myID = myID;
		ClientDatabase = new HashMap<String, SecretKey>();
	}

	private void readASKey() throws IOException {
		System.out.println(String.format("Reading AS%S Shared Key...", myID));
		byte[] decodedKey = Shared.base64ToBytes(Shared.readFile(String.format("Shared/AS%sKey.txt", myID)));
		SecretKey ASKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
		ClientDatabase.put("AS", ASKey);
		Display.printDashedLine();
	}

	private void createDatabase() throws IOException {
		readASKey();
		Shared.printKeysDatabase(ClientDatabase);
	}

	private String doASExchange() throws IOException, ClassNotFoundException, InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException,
			IllegalBlockSizeException {
		Socket connectSocket = new Socket(Shared.KDCIP, Shared.ASPortNumber);
		OutputStream outputStream = connectSocket.getOutputStream();
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

		System.out.println("Started AS Exchange...");

		// Send KRB_AS_REQ
		Shared.waitForKey();
		Display.printDashedLine();
		System.out.println("Sending KRB_AS_REQ...");

		long currentTime = System.currentTimeMillis();
		KRB_201_Support_Times times = new KRB_201_Support_Times(currentTime, currentTime + 60 * 60 * 1000); // 1 Hr
																											// Ticket
		String nonce1 = SKC.generateNonce();
		Object outputObject = new KRB_201_AS_REQ(Shared.KRB_AS_REQ, myID, Shared.REALM, Shared.TGSID, times, nonce1);
		Shared.sendObject("Client", objectOutputStream, outputObject);

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Extract information from KRB_AS_ERR_PREAUTH_REQ for FAST channel and OTP
		// Preauthentication
		Display.printSolidLine();
		InputStream inputStream = connectSocket.getInputStream();
		ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
		KRB_202_AS_ERR_PREAUTH_REQUIRED asErrorPreAuthRequired = (KRB_202_AS_ERR_PREAUTH_REQUIRED) objectInputStream
				.readObject();
		String msgCode = asErrorPreAuthRequired.getMsgCode();
		Shared.checkMsgCode(msgCode, Shared.KRB_AS_ERR_PREAUTH_REQ);

		SecretKey fastSessionKey = asErrorPreAuthRequired.getFastSessionKey();

		KRB_202_Support_PA_OTP_CHALLENGE paOTPChallenge = asErrorPreAuthRequired.getPaOTPChallenge();
		String otpNonce = paOTPChallenge.getNonce();
		int otpSizeBits = paOTPChallenge.getOtpSizeBits();
		int otpIterationCount = paOTPChallenge.getIterationCount();
		String otpSeed = paOTPChallenge.getSeed();

		System.out.println(String.format("Received %s msg from AS:", msgCode));
		System.out.println(String.format("%-30s%s", "msgCode", msgCode));
		SKC.printKey("FAST Armor Session", fastSessionKey);
		System.out.println(String.format("%-30s%s", "OTP nonce", otpNonce));
		System.out.println(String.format("%-30s%s", "OTP otpSizeBits", otpSizeBits));
		System.out.println(String.format("%-30s%s", "OTP iterationCount", otpIterationCount));
		System.out.println(String.format("%-30s%s", "OTP seed", otpSeed));

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Generate FAST Armor Key
		Display.printSolidLine();
		System.out.println("Generating FAST Armor Key...");
		SecretKey fastArmorKey = SKC.combineSecretKeys("FAST Armor", fastSessionKey, ClientDatabase.get("AS"),
				Shared.AlgorithmAES);

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Generate OTP Value using parameters sent by AS
		Display.printSolidLine();
		System.out.println("Generating OTP...");
		String preOTPStr = Hex.encodeHexString(ClientDatabase.get("AS").getEncoded()) + otpSeed;
		byte[] OTPBytes = SKC.generateOTP(otpSizeBits, otpIterationCount, preOTPStr);
		String generatedOTP = Hex.encodeHexString(OTPBytes);
		System.out.println(String.format("%db OTP: %s\n", OTPBytes.length * 8, generatedOTP));

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Generate encrypted paOTPRequest using FAST Armor Key and send
		// KRB_203_AS_REQ_WITH_OTP
		Shared.waitForKey();
		Display.printSolidLine();
		System.out.println("\nSending KRB_AS_REQ_WITH_OTP...");
		KRB_203_Support_PA_OTP_REQ paOTPRequest = new KRB_203_Support_PA_OTP_REQ(otpNonce, generatedOTP);
		outputObject = new KRB_203_AS_REQ_WITH_OTP(Shared.KRB_AS_REQ_WITH_OTP, myID, Shared.REALM, Shared.TGSID, times,
				nonce1, paOTPRequest.getPAOTPRequestEncryptedEncoded("fastArmorKey", fastArmorKey));
		Shared.sendObject("Client", objectOutputStream, outputObject);

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Extract information from KRB_204_AS_REP, obtain Session Key between TGS &
		// Client and return encrypted TGS Ticket as it is for further communication
		// with TGS
		Display.printDashedLine();
		KRB_204_AS_REP asReply = (KRB_204_AS_REP) objectInputStream.readObject();
		msgCode = asReply.getMsgCode();
		Shared.checkMsgCode(msgCode, Shared.KRB_AS_REP);

		String realm = asReply.getRealm();
		Shared.checkRealm(realm);

		String tgsTicketEncryptedEncodedData = asReply.getTgsTicketEncryptedEncodedData();
		String clientDataEncryptedEncoded = asReply.getClientDataEncryptedEncoded();

		System.out.println(String.format("Received %s msg from AS:", msgCode));
		System.out.println(String.format("%-30s%s", "msgCode", msgCode));
		System.out.println(String.format("%-30s%s", "realm", realm));
		System.out.println(String.format("%-30s%s\n", "clientID", asReply.getClientID()));
		System.out.println(String.format("%-30s%s\n", "tgsTicket", tgsTicketEncryptedEncodedData));
		System.out.println(String.format("%-30s%s\n", "clientData", clientDataEncryptedEncoded));

		String clientData = SKC.decrypt("ClientData", "fastArmorKey", Shared.transformation, clientDataEncryptedEncoded,
				fastArmorKey);

		String[] clientDataSplit = clientData.split(Shared.delimiter);
		String TGSKeyEncoded = clientDataSplit[0];
		long startTime = Long.parseLong(clientDataSplit[1]);
		long endTime = Long.parseLong(clientDataSplit[2]);
		String receivedNonce1 = clientDataSplit[3];
		if (!receivedNonce1.equals(nonce1)) {
			System.out.println("Nonce1 doesn't match! Message authentication failed! Terminating...");
			System.exit(-1);
		}

		byte[] decodedKey = Shared.base64ToBytes(TGSKeyEncoded);
		SecretKey TGSKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
		ClientDatabase.put(Shared.TGSID, TGSKey);
		SKC.printKey("TGS-Client Session", TGSKey);
		System.out.println(String.format("%-30s%s", "startTime",
				Instant.ofEpochMilli(startTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
		System.out.println(String.format("%-30s%s", "endTime",
				Instant.ofEpochMilli(endTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
		System.out.println(String.format("%-30s%s", "receivedNonce1", receivedNonce1));
		System.out.println(String.format("%-30s%s", "TGSRealm", clientDataSplit[4]));
		System.out.println(String.format("%-30s%s", "TGSID", clientDataSplit[5]));

		System.out.println("\nNonce1 matched! AS Reply  is authenticated!");

		Display.printDashedLine();

		connectSocket.close();

		return tgsTicketEncryptedEncodedData;
	}

	private String doTGSExchange(String tgsTicketEncryptedEncodedData) throws UnknownHostException, IOException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		Shared.printKeysDatabase(ClientDatabase);
		Socket connectSocket = new Socket(Shared.KDCIP, Shared.TGSPortNumber);
		OutputStream outputStream = connectSocket.getOutputStream();
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

		System.out.println("Started TGS Exchange...");

		// Send KRB_TGS_REQ containing Encrypted TGS Ticket and Encrypted Authenticator1
		Shared.waitForKey();
		Display.printDashedLine();
		System.out.println("Sending KRB_TGS_REQ...");

		long currentTime = System.currentTimeMillis();
		KRB_201_Support_Times times = new KRB_201_Support_Times(currentTime, currentTime + 60 * 60 * 1000); // 1 Hr
																											// Ticket
		String nonce2 = SKC.generateNonce();

		KRB_301_Support_TGS_REQ_Authenticator1 authenticator1 = new KRB_301_Support_TGS_REQ_Authenticator1(myID,
				Shared.REALM, Long.toString(currentTime));
		SecretKey tgsSessionKey = ClientDatabase.get(Shared.TGSID);
		String authenticator1EncryptedEncodedData = authenticator1.getEncodedEncryptedTicketData("tgsSessionKey",
				tgsSessionKey);

		KRB_301_TGS_REQ outputObject = new KRB_301_TGS_REQ(Shared.KRB_TGS_REQ, Shared.APID, times, nonce2,
				tgsTicketEncryptedEncodedData, authenticator1EncryptedEncodedData);

		Shared.sendObject("Client", objectOutputStream, outputObject);

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Extract information from KRB_302_TGS_REP, obtain Session Key between AP &
		// Client and return encrypted AP Ticket as it is for further communication
		// with AP
		Display.printDashedLine();
		InputStream inputStream = connectSocket.getInputStream();
		ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
		KRB_302_TGS_REP tgsReply = (KRB_302_TGS_REP) objectInputStream.readObject();

		String msgCode = tgsReply.getMsgCode();
		Shared.checkMsgCode(msgCode, Shared.KRB_TGS_REP);

		String realm = tgsReply.getRealm();
		Shared.checkRealm(realm);

		String apTicketEncryptedEncodedData = tgsReply.getApTicketEncryptedEncodedData();
		String clientDataEncryptedEncoded = tgsReply.getClientDataEncryptedEncoded();

		System.out.println(String.format("Received %s msg from TGS:", msgCode));
		System.out.println(String.format("%-30s%s", "msgCode", msgCode));
		System.out.println(String.format("%-30s%s", "realm", realm));
		System.out.println(String.format("%-30s%s\n", "clientID", tgsReply.getClientID()));
		System.out.println(String.format("%-30s%s\n", "apTicket", apTicketEncryptedEncodedData));
		System.out.println(String.format("%-30s%s\n", "clientData", clientDataEncryptedEncoded));

		String clientData = SKC.decrypt("ClientData", "tgsSessionKey", Shared.transformation,
				clientDataEncryptedEncoded, ClientDatabase.get(Shared.TGSID));

		String[] clientDataSplit = clientData.split(Shared.delimiter);
		String APKeyEncoded = clientDataSplit[0];
		long startTime = Long.parseLong(clientDataSplit[1]);
		long endTime = Long.parseLong(clientDataSplit[2]);
		String receivedNonce2 = clientDataSplit[3];
		if (!receivedNonce2.equals(nonce2)) {
			System.out.println("Nonce2 doesn't match! Message authentication failed! Terminating...");
			System.exit(-1);
		}

		byte[] decodedKey = Shared.base64ToBytes(APKeyEncoded);
		SecretKey APKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
		ClientDatabase.put(Shared.APID, APKey);
		SKC.printKey("AP-Client Session", APKey);
		System.out.println(String.format("%-30s%s", "startTime",
				Instant.ofEpochMilli(startTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
		System.out.println(String.format("%-30s%s", "endTime",
				Instant.ofEpochMilli(endTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
		System.out.println(String.format("%-30s%s", "receivedNonce2", receivedNonce2));
		System.out.println(String.format("%-30s%s", "APRealm", clientDataSplit[4]));
		System.out.println(String.format("%-30s%s", "APID", clientDataSplit[5]));

		System.out.println("\nNonce2 matched! TGS Reply is authenticated!");

		Display.printDashedLine();

		connectSocket.close();

		return apTicketEncryptedEncodedData;
	}

	private void doAPExchange(String apTicketEncryptedEncodedData) throws UnknownHostException, IOException,
			InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		Shared.printKeysDatabase(ClientDatabase);
		Socket connectSocket = new Socket(Shared.KDCIP, Shared.APPortNumber);
		OutputStream outputStream = connectSocket.getOutputStream();
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);

		System.out.println("Started AP Exchange...");

		// Send KRB_AP_REQ containing Encrypted AP Ticket and Encrypted Authenticator2
		Shared.waitForKey();
		Display.printDashedLine();
		System.out.println("Sending KRB_AP_REQ...");

		String ts2 = Long.toString(System.currentTimeMillis());
		KRB_401_Support_AP_REQ_Authenticator2 authenticator2 = new KRB_401_Support_AP_REQ_Authenticator2(myID,
				Shared.REALM, ts2);
		SecretKey apSessionKey = ClientDatabase.get(Shared.APID);
		String authenticator2EncryptedEncodedData = authenticator2.getEncodedEncryptedTicketData("apSessionKey",
				apSessionKey);

		KRB_401_AP_REQ outputObject = new KRB_401_AP_REQ(Shared.KRB_AP_REQ, apTicketEncryptedEncodedData,
				authenticator2EncryptedEncodedData);

		Shared.sendObject("Client", objectOutputStream, outputObject);

		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		// Extract information from KRB_402_AP_REP, Keberos Authentication Protocol
		// completes here, Client can obtain any service from AP further....
		Display.printDashedLine();
		InputStream inputStream = connectSocket.getInputStream();
		ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
		KRB_402_AP_REP apReply = (KRB_402_AP_REP) objectInputStream.readObject();

		String msgCode = apReply.getMsgCode();
		Shared.checkMsgCode(msgCode, Shared.KRB_AP_REP);

		String clientDataEncryptedEncoded = apReply.getClientDataEncryptedEncoded();

		System.out.println(String.format("Received %s msg from AP:", msgCode));
		System.out.println(String.format("%-30s%s", "msgCode", msgCode));
		System.out.println(String.format("%-30s%s\n", "clientData", clientDataEncryptedEncoded));

		String clientData = SKC.decrypt("ClientData", "apSessionKey", Shared.transformation, clientDataEncryptedEncoded,
				ClientDatabase.get(Shared.APID));

		String[] clientDataSplit = clientData.split(Shared.delimiter);
		String ts2Received = clientDataSplit[0];
		if (!ts2Received.equals(ts2)) {
			System.out.println("ts2 doesn't match! Message authentication failed! Terminating...");
			System.exit(-1);
		}

		System.out.println(String.format("%-30s%s", "ts2Received", ts2Received));

		System.out.println("\nts2 matched! AP Reply is authenticated!");

		Display.printDashedLine();

		System.out.println(
				"Kerberos Authentication Protocol with OTP Preauthentication using FAST Armor Successfully Completed! Client can obtain any service from the AP server further...");

		connectSocket.close();
	}

	public static void main(String[] args)
			throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		if (args.length != 1) {
			System.err.println("Usage: java kpa.E4_Client <ClientID>");
			System.exit(1);
		}
		String myID = args[0];

		E4_Client client = new E4_Client(myID);
		client.createDatabase();
		String tgsTicket = client.doASExchange();
		String apTicket = client.doTGSExchange(tgsTicket);
		client.doAPExchange(apTicket);
	}
}
