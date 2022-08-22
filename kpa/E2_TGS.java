package kpa;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
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

public class E2_TGS {
	String myID;
	private boolean generateKeysFlag;
	protected Map<String, SecretKey> TGSDatabase;

	public E2_TGS(String myID, boolean generateKeyFlag) {
		this.myID = myID;
		this.generateKeysFlag = generateKeyFlag;
		TGSDatabase = new HashMap<String, SecretKey>();

		Display.printDashedLine();
		System.out.println(String.format("Started TGS Server with ID = %s...", myID));
		Display.printDashedLine();
	}

	private void readASKey() throws IOException {
		System.out.println(String.format("Reading AS%S Shared Key...", myID));
		byte[] decodedKey = Shared.base64ToBytes(Shared.readFile(String.format("Shared/AS%sKey.txt", myID)));
		SecretKey ASKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
		TGSDatabase.put("AS", ASKey);
		Display.printDashedLine();
	}

	private void createAPKeys() throws NoSuchAlgorithmException, IOException {
		int numAPServers = 1;
		if (generateKeysFlag) {
			System.out.println(String.format("Generating %d TGSAP Shared Keys...", numAPServers));
		} else {
			System.out.println(String.format("Reading %d TGSAP Shared Keys...", numAPServers));
		}
		for (int i = 1; i <= numAPServers; i++) {
			String APID = String.format("AP%s", i);
			SecretKey key;
			if (generateKeysFlag) {
				System.out.println();
				key = SKC.generateKey("TGS-AP", Shared.AlgorithmAES, Shared.AlgorithmKeySizeBits256);
				Shared.writeFile(String.format("Shared/%s%sKey.txt", myID, APID),
						Shared.bytesToBase64(key.getEncoded()));
			} else {
				byte[] decodedKey = Shared
						.base64ToBytes(Shared.readFile(String.format("Shared/%s%sKey.txt", myID, APID)));
				key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
			}
			TGSDatabase.put(APID, key);
		}
		Display.printDashedLine();
	}

	private void createDatabase() throws IOException, NoSuchAlgorithmException {
		readASKey();
		createAPKeys();
		Shared.printKeysDatabase(TGSDatabase);
	}

	private void startListening() {
		boolean listening = true;
		try (ServerSocket serverSocket = new ServerSocket(Shared.TGSPortNumber)) {
			while (listening) {
				System.out.println(String.format("\nStarted listening on Socket: %s:%s",
						serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort()));
				Socket connectSocket = serverSocket.accept();
				new TGSThread(this, connectSocket).start();
			}
		} catch (IOException e) {
			System.err.println("Could not listen on port " + Shared.TGSPortNumber);
			System.exit(-1);
		}
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		String myID = Shared.TGSID;
		boolean generateKeysFlag = false;
		E2_TGS tgs = new E2_TGS(myID, generateKeysFlag);

		tgs.createDatabase();

		tgs.startListening();
	}
}

class TGSThread extends Thread {
	private Socket socket = null;
	private String remoteSocketAddress;
	private E2_TGS tgs;

	private static final int WAITING_301 = 0;
	private static final int SENT_302 = 1;
	private int state = WAITING_301;

	public TGSThread(E2_TGS tgs, Socket socket) {
		super("MultiClientServerThread");
		this.tgs = tgs;
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

			KRB_301_TGS_REQ inputObject = (KRB_301_TGS_REQ) objectInputStream.readObject();
			if (inputObject != null) {
				KRB_302_TGS_REP outputObject = processInput(inputObject);
				Shared.waitForKey();
				Shared.sendObject("TGS", objectOutputStream, outputObject);
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

	public KRB_302_TGS_REP processInput(KRB_301_TGS_REQ inputObject)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		KRB_302_TGS_REP theOutput = null;

		if (state == WAITING_301) {

			// Extract information from KRB_301_TGS_REQ
			Display.printDashedLine();
			String msgCode = inputObject.getMsgCode();
			Shared.checkMsgCode(msgCode, Shared.KRB_TGS_REQ);

			String apID = inputObject.getApID();
			KRB_201_Support_Times times = inputObject.getTimes();
			String nonce2 = inputObject.getNonce2();
			String tgsTicketEncryptedEncodedData = inputObject.getTgsTicketEncryptedEncodedData();
			String authenticator1EncryptedEncodedData = inputObject.getAuthenticator1EncryptedEncodedData();

			System.out.println(String.format("Received %s msg from client %s:", msgCode, remoteSocketAddress));
			System.out.println(String.format("%-30s%s", "msgCode", msgCode));
			System.out.println(String.format("%-30s%s", "apID", apID));
			System.out.println(String.format("%-30s%s", "startTime",
					Instant.ofEpochMilli(times.getStartTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "endTime",
					Instant.ofEpochMilli(times.getEndTime()).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "nonce2", nonce2));
			System.out.println(String.format("\n%-30s%s\n", "tgsTicket", tgsTicketEncryptedEncodedData));
			System.out.println(String.format("%-30s%s\n", "authenticator1", authenticator1EncryptedEncodedData));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Decrypt TGS Ticket using shared key between AS & TGS and extract Session
			// Key between TGS & Client
			Display.printDashedLine();
			SecretKey asKey = tgs.TGSDatabase.get("AS");
			String tgsTicketStr = SKC.decrypt("TGSTicket", "asKey", Shared.transformation,
					tgsTicketEncryptedEncodedData, asKey);

			String[] tgsTicketStrSplit = tgsTicketStr.split(Shared.delimiter);
			byte[] decodedKey = Shared.base64ToBytes(tgsTicketStrSplit[0]);
			SecretKey clientSessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
			SKC.printKey("TGS-Client Session", clientSessionKey);

			String realmFromTicket = tgsTicketStrSplit[1];
			Shared.checkRealm(realmFromTicket);

			String clientIDFromTicket = tgsTicketStrSplit[2];
			String clientAddressFromTicket = tgsTicketStrSplit[3];
			long startTime = Long.parseLong(tgsTicketStrSplit[4]);
			long endTime = Long.parseLong(tgsTicketStrSplit[5]);

			System.out.println(String.format("%-30s%s", "realmFromTicket", realmFromTicket));
			System.out.println(String.format("%-30s%s", "clientIDFromTicket", clientIDFromTicket));
			System.out.println(String.format("%-30s%s", "clientAddressFromTicket", clientAddressFromTicket));
			System.out.println(String.format("%-30s%s", "startTime",
					Instant.ofEpochMilli(startTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "endTime",
					Instant.ofEpochMilli(endTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Decrypt Authenticator1 using Session Key obtained from TGS Ticket and verify client information
			Display.printDashedLine();
			String authenticator1Str = SKC.decrypt("Authenticator1", "clientSessionKey", Shared.transformation,
					authenticator1EncryptedEncodedData, clientSessionKey);

			String[] authenticator1StrSplit = authenticator1Str.split(Shared.delimiter);
			String clientIDFromAuthenticator1 = authenticator1StrSplit[0];
			if (!clientIDFromAuthenticator1.equals(clientIDFromTicket)) {
				System.out.println(String.format(
						"Unexpected clientID! Expecting %s clientID (as in TGSTicket) but received %s (in Authenticator1)",
						clientIDFromTicket, clientIDFromAuthenticator1));
				System.exit(1);
			}

			String realmFromAuthenticator1 = authenticator1StrSplit[1];
			Shared.checkRealm(realmFromAuthenticator1);

			long TS1 = Long.parseLong(authenticator1StrSplit[2]);

			System.out.println(String.format("%-30s%s", "clientIDFromAuthenticator1", clientIDFromAuthenticator1));
			System.out.println(String.format("%-30s%s", "realmFromAuthenticator1", realmFromAuthenticator1));
			System.out.println(String.format("%-30s%d\n", "TS1", TS1));
			System.out.println(String.format("clientID %s macthed (as in Ticket) with received %s (in Authenticator1)!",
					clientIDFromTicket, clientIDFromAuthenticator1));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Generate APTicket, Session Key for AP-Client Communication and send KRB_302_TGS_REP
			Display.printSolidLine();
			System.out.println("\nSending KRB_TGS_REP...");

			System.out.println("\nGenerating APTicket...");
			SecretKey apKey = tgs.TGSDatabase.get(apID);
			SecretKey apSessionKey = SKC.generateKey("AP-Client Session", Shared.AlgorithmAES,
					Shared.AlgorithmKeySizeBits256);

			KRB_302_Support_AP_Ticket apTicket = new KRB_302_Support_AP_Ticket(apSessionKey, realmFromTicket,
					clientIDFromTicket, clientAddressFromTicket, times);
			String apTicketEncryptedEncodedData = apTicket.getEncodedEncryptedTicketData("apKey", apKey);

			KRB_302_Support_TGS_REP_ClientData clientData = new KRB_302_Support_TGS_REP_ClientData(apSessionKey, times,
					nonce2, realmFromTicket, apID);
			String clientDataEncryptedEncodedData = clientData.getEncodedEncryptedTicketData("clientSessionKey",
					clientSessionKey);

			theOutput = new KRB_302_TGS_REP(Shared.KRB_TGS_REP, realmFromTicket, clientIDFromTicket,
					apTicketEncryptedEncodedData, clientDataEncryptedEncodedData);

			state = SENT_302;
		} else {
			theOutput = null;
			state = WAITING_301;
		}
		return theOutput;
	}
}
