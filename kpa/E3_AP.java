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

public class E3_AP {
	private String myID;
	protected Map<String, SecretKey> APDatabase;

	public E3_AP(String myID) {
		this.myID = myID;
		APDatabase = new HashMap<String, SecretKey>();

		Display.printDashedLine();
		System.out.println(String.format("Started AP Server with ID = %s...", myID));
		Display.printDashedLine();
	}

	private void readTGSKey() throws IOException {
		System.out.println(String.format("Reading TGS1%S Shared Key....", myID));
		byte[] decodedKey = Shared.base64ToBytes(Shared.readFile(String.format("Shared/TGS1%sKey.txt", myID)));
		SecretKey TGS1Key = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
		APDatabase.put(Shared.TGSID, TGS1Key);
		Display.printDashedLine();
	}

	private void createDatabase() throws IOException {
		readTGSKey();
		Shared.printKeysDatabase(APDatabase);
	}

	private void startListening() {
		boolean listening = true;
		try (ServerSocket serverSocket = new ServerSocket(Shared.APPortNumber)) {
			while (listening) {
				System.out.println(String.format("\nStarted listening on Socket: %s:%s",
						serverSocket.getInetAddress().getHostAddress(), serverSocket.getLocalPort()));
				new APChatThread(this, serverSocket.accept()).start();
			}
		} catch (IOException e) {
			System.err.println("Could not listen on port " + Shared.APPortNumber);
			System.exit(-1);
		}
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		String myID = Shared.APID;
		E3_AP apChat = new E3_AP(myID);

		apChat.createDatabase();
		apChat.startListening();
	}
}

class APChatThread extends Thread {
	private Socket socket = null;
	private String remoteSocketAddress;
	private E3_AP ap;

	private static final int WAITING_301 = 0;
	private static final int SENT_302 = 1;
	private int state = WAITING_301;

	public APChatThread(E3_AP ap, Socket socket) {
		super("MultiClientServerThread");
		this.ap = ap;
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

			KRB_401_AP_REQ inputObject = (KRB_401_AP_REQ) objectInputStream.readObject();
			if (inputObject != null) {
				KRB_402_AP_REP outputObject = (KRB_402_AP_REP) processInput(inputObject);
				Shared.waitForKey();
				Shared.sendObject("AP", objectOutputStream, outputObject);
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

	public Object processInput(KRB_401_AP_REQ inputObject)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
		Object theOutput = null;

		if (state == WAITING_301) {

			// Extract information from KRB_401_AP_REQ
			Display.printDashedLine();
			String msgCode = inputObject.getMsgCode();
			Shared.checkMsgCode(msgCode, Shared.KRB_AP_REQ);

			String apTicketEncryptedEncodedData = inputObject.getApTicketEncryptedEncodedData();
			String authenticator2EncryptedEncodedData = inputObject.getAuthenticator2EncryptedEncodedData();

			System.out.println(String.format("Received %s msg from client %s:", msgCode, remoteSocketAddress));
			System.out.println(String.format("%-30s%s", "msgCode", msgCode));
			System.out.println(String.format("\n%-30s%s\n", "apTicket", apTicketEncryptedEncodedData));
			System.out.println(String.format("%-30s%s\n", "authenticator2", authenticator2EncryptedEncodedData));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Decrypt APTicket using shared key between TGS & AP and extract Session Key
			// between AP & Client
			Display.printDashedLine();
			SecretKey tgsKey = ap.APDatabase.get(Shared.TGSID);
			String apTicketStr = SKC.decrypt("APTicket", "asKey", Shared.transformation, apTicketEncryptedEncodedData,
					tgsKey);

			String[] apTicketStrSplit = apTicketStr.split(Shared.delimiter);
			byte[] decodedKey = Shared.base64ToBytes(apTicketStrSplit[0]);
			SecretKey clientSessionKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, Shared.AlgorithmAES);
			SKC.printKey("AP-Client Session", clientSessionKey);

			String realmFromTicket = apTicketStrSplit[1];
			Shared.checkRealm(realmFromTicket);

			String clientIDFromTicket = apTicketStrSplit[2];
			String clientAddressFromTicket = apTicketStrSplit[3];
			long startTime = Long.parseLong(apTicketStrSplit[4]);
			long endTime = Long.parseLong(apTicketStrSplit[5]);

			System.out.println(String.format("%-30s%s", "realmFromTicket", realmFromTicket));
			System.out.println(String.format("%-30s%s", "clientIDFromTicket", clientIDFromTicket));
			System.out.println(String.format("%-30s%s", "clientAddressFromTicket", clientAddressFromTicket));
			System.out.println(String.format("%-30s%s", "startTime",
					Instant.ofEpochMilli(startTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));
			System.out.println(String.format("%-30s%s", "endTime",
					Instant.ofEpochMilli(endTime).atZone(ZoneId.systemDefault()).toLocalDateTime()));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Decrypt Authenticator2 using Session Key obtained from APTicket and verify client information
			Display.printDashedLine();
			String authenticator2Str = SKC.decrypt("Authenticator2", "clientSessionKey", Shared.transformation,
					authenticator2EncryptedEncodedData, clientSessionKey);

			String[] authenticator2StrSplit = authenticator2Str.split(Shared.delimiter);
			String clientIDFromAuthenticator2 = authenticator2StrSplit[0];
			if (!clientIDFromAuthenticator2.equals(clientIDFromTicket)) {
				System.out.println(String.format(
						"Unexpected clientID! Expecting %s clientID (as in APTicket) but received %s (in Authenticator2)",
						clientIDFromTicket, clientIDFromAuthenticator2));
				System.exit(1);
			}

			String realmFromAuthenticator2 = authenticator2StrSplit[1];
			Shared.checkRealm(realmFromAuthenticator2);

			long ts2 = Long.parseLong(authenticator2StrSplit[2]);

			System.out.println(String.format("%-30s%s", "clientIDFromAuthenticator2", clientIDFromAuthenticator2));
			System.out.println(String.format("%-30s%s", "realmFromAuthenticator2", realmFromAuthenticator2));
			System.out.println(String.format("%-30s%d\n", "TS2", ts2));
			System.out.println(String.format("clientID %s macthed (as in Ticket) with received %s (in Authenticator2)!",
					clientIDFromTicket, clientIDFromAuthenticator2));

			////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

			// Send KRB_AP_REP for the authenticated client as final message in Kerberos authentication, further any service can be provided...
			Display.printSolidLine();
			System.out.println("\nSending KRB_AP_REP...");

			KRB_402_Support_AP_REP_ClientData clientData = new KRB_402_Support_AP_REP_ClientData(Long.toString(ts2));
			String clientDataEncryptedEncodedData = clientData.getEncodedEncryptedTicketData("clientSessionKey",
					clientSessionKey);

			theOutput = new KRB_402_AP_REP(Shared.KRB_AP_REP, clientDataEncryptedEncodedData);

			System.out.println(
					"\nClient is Authenticated! End of Kerberos Authentication Protocol, AP can provide any service further to this client...");
			state = SENT_302;
		} else {
			theOutput = "Bye from AP Server";
			state = WAITING_301;
		}
		return theOutput;
	}
}
