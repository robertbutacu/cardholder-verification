package com.cardholder.verification;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadT1Client;

import static com.cardholder.verification.Constants.*;

public abstract class Terminal {
    protected static String hostName = Constants.DEFAULT_HOST_NAME;

    protected static int port = Constants.DEFAULT_PORT;
    
	protected final String PUBLIC_KEY_FILENAME = "";

    protected CadClientInterface cad;
    
    protected static byte[] staticKeyData = null;

    
    public Terminal(String hostName, int hostPort)
            throws Exception {
        Socket socket = new Socket(hostName, hostPort);
        socket.setTcpNoDelay(true);
        BufferedInputStream input = new BufferedInputStream(socket
                .getInputStream());
        BufferedOutputStream output = new BufferedOutputStream(socket
                .getOutputStream());
        cad = new CadT1Client(input, output);
     }

    void powerUp() throws Exception {
        cad.powerUp();
    }

    void powerDown() {
    try {
        cad.powerDown(true);
    } catch (Exception e) {}
    }

    void selectApplet() throws Exception {

        // C-APDU: [CLA, INS, P1, P2, LC, [ AID_TRANSIT ]]

        Apdu apdu = new Apdu();
        apdu.command[Apdu.CLA] = CLA_ISO7816;
        apdu.command[Apdu.INS] = INS_SELECT;
        apdu.command[Apdu.P1] = 0x04;
        apdu.command[Apdu.P2] = 0;

        apdu.setDataIn(AID_TRANSIT);

        System.out.println(apdu);
        cad.exchangeApdu(apdu);
        System.out.println(apdu);

        if (apdu.getStatus() == SW_NO_ERROR) {
            System.out.println("OK");
        } else {
            System.out.println("Error: " + apdu.getStatus());
        }
    }

    /**
     * Verifies the user-provided PIN against the on-card PIN.
     *
     * @param pin
     *            The PIN
     * @throws Exception
     */
    void verifyPIN(byte[] pin) throws Exception {

        // C-APDU: [CLA, INS, P1, P2, LC, [ PIN ]]

        Apdu apdu = new Apdu();
        apdu.command[Apdu.CLA] = CLA_ISO7816;
        apdu.command[Apdu.INS] = INS_VERIFY;
        apdu.command[Apdu.P1] = 0;
        apdu.command[Apdu.P2] = 0;

        apdu.setDataIn(pin);

        System.out.println(apdu);
        cad.exchangeApdu(apdu);
        System.out.println(apdu);

        if (apdu.getStatus() == SW_NO_ERROR) {
            System.out.println("OK");
        } else {
            System.out.println("Error: " + apdu.getStatus());
        }
    }
    
    protected byte[] sendRequest(byte requestCode, byte[] requestMessage)
            throws Exception {

        Apdu apdu = new Apdu();
        apdu.command[Apdu.CLA] = TRANSIT_CLA;
        apdu.command[Apdu.INS] = requestCode;
        apdu.command[Apdu.P1] = 0;
        apdu.command[Apdu.P2] = 0;

        apdu.setDataIn(requestMessage);

        System.err.println(apdu);
        cad.exchangeApdu(apdu);
        System.err.println(apdu);

        if (apdu.getStatus() == SW_NO_ERROR) {

            byte[] responseMessage = apdu.getDataOut();
            System.out.println("Response: " + responseMessage);

        }
        return null;
    }
    
    void initializeSession() throws Exception {

        // C-APDU: [CLA, INS, P1, P2, LC, [4-bytes Host Challenge]]

        Apdu apdu = new Apdu();
        apdu.command[Apdu.CLA] = TRANSIT_CLA;
        apdu.command[Apdu.INS] = INITIALIZE_SESSION;
        apdu.command[Apdu.P1] = 0;
        apdu.command[Apdu.P2] = 0;

        // Generate card challenge

        byte[] hostChallenge = generateHostChallenge();

        byte[] data = new byte[hostChallenge.length];
        System.arraycopy(hostChallenge, 0, data, 0, hostChallenge.length);
        apdu.setDataIn(data);

        System.err.println(apdu);
        cad.exchangeApdu(apdu);
        System.err.println(apdu);

        if (apdu.getStatus() == SW_NO_ERROR) {

            // R-APDU: [[4-bytes Card Challenge], [2-bytes Status Word],
            // [8-bytes MAC]]

            data = apdu.getDataOut();

            // Check status word

            byte[] cardChallenge = new byte[CHALLENGE_LENGTH];
            System.arraycopy(data, 0, cardChallenge, 0, CHALLENGE_LENGTH);

            // Generate key derivation data from host challenge and card
            // challenge
           /* byte[] keyDerivationData = generateKeyDerivationData(hostChallenge,
                    cardChallenge);

            // Generate session key from derivation data
            generateSessionKey(keyDerivationData);

        // Initialize MAC with current session key for verification
        mac = new Mac(sessionKey);

            // Check response message MAC

            if (mac.checkMAC(data, apdu.getLe() - MAC_LENGTH)) {
                System.err.println("OK");
            } else {
        throw new Exception("InitializeSession: Wrong signature");
            }
        } else {
        throw new Exception("InitializeSession: Error " + apdu.getStatus());
        }*/
        	}
        }


    protected short getShort(byte[] buffer, int offset) {
        return (short) ((((short) buffer[offset]) << 8) | buffer[offset + 1]);
    }
    
    protected byte[] generateHostChallenge() {
        byte[] hostChallenge = new byte[CHALLENGE_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(hostChallenge);
        return hostChallenge;
    }
    
    public static byte[] parseByteArray(String s) {
    byte[] array = new byte[s.length() / 2];
    for (int i = 0; i < s.length(); i += 2) {
        array[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
    }
    return array;
    }
    
    protected void copyShort(short i, byte[] buffer, int offset) {
        buffer[offset] = (byte) ((i >> 8) & 0x00ff);
        buffer[offset + 1] = (byte) (i & 0x00ff);
    }
    
    protected PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
        byte[] data = Base64.getDecoder().decode(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePublic(spec);
    }
}
