package com.cardholder.verification;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadT1Client;

import static com.cardholder.verification.Constants.*;

public abstract class Terminal {
    protected static String hostName = Constants.DEFAULT_HOST_NAME;

    protected static int port = Constants.DEFAULT_PORT;
    
	protected final String PUBLIC_KEY_FILENAME = "E:\\Projects\\cardholder-verification\\src\\com\\cardholder\\verification\\public-key.txt";

    protected CadClientInterface cad;
    
    protected static byte[] staticKeyData = null;
    
    private Mac mac;
   
	private RSAPublicKey publicKey;
	
	private Cipher cipher;
    
    private SecretKeyFactory keyFactory;

	private SecretKey sessionKey;
    
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
            byte[] keyDerivationData = generateKeyDerivationData(hostChallenge,
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
        }
        	}

    protected void generateSessionKey(byte[] keyDerivationData)
        throws Exception {
    	byte[] paddedData = pad(keyDerivationData, 0, keyDerivationData.length, cipher.getBlockSize());
    	byte[] sessionKeyData = fixParity(cipher.doFinal(paddedData));
    	// Generate new session key from derivation data
    	KeySpec keySpec = new DESKeySpec(sessionKeyData);
    	sessionKey = keyFactory.generateSecret(keySpec);
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
    
    private byte[] pad(byte[] msg, int offset, int length, int blockLength)  {
    // Add 1 to add 0x80 at the end.
    int paddedLength = length + 1;
    int numBlocks = (int) (paddedLength / blockLength);
    int remBytes = paddedLength - (numBlocks * blockLength);
    if (remBytes > 0) {
        numBlocks++;
    }
    byte[] paddedMsg = new byte[numBlocks * blockLength];
    System.arraycopy(msg, offset, paddedMsg, 0, length);
    paddedMsg[length] = (byte) 0x80;
    // Fill message with zeroes to fit blocks
    for (int i = (length + 1); i < paddedMsg.length; i++) {
        paddedMsg[i] = (byte) 0x00;
    }
    return paddedMsg;
    }

    private byte[] fixParity(byte[] keyData) {
    for (int i = 0; i < keyData.length; i++) {
        short parity = 0;
        keyData[i] &= 0xFE;
        for (int j = 1; j < 8; j++) {
        if ((keyData[i] & ((byte) (1 << j))) != 0) {
            parity++;
        }
        }
        if ((parity % 2) == 0) {
        keyData[i] |= 1;
        }
    }
    return keyData;
    }
    
    protected byte[] generateKeyDerivationData(byte[] hostChallenge,
            byte[] cardChallenge) {

        // Derivation data: [[4-bytes host challenge], [4-bytes card challenge]]

        byte[] keyDerivationData = new byte[CHALLENGE_LENGTH * 2];

        // Append host challenge to derivation data
        System.arraycopy(hostChallenge, 0, keyDerivationData, 0,
                CHALLENGE_LENGTH);
        // Append card challenge to derivation data
        System.arraycopy(cardChallenge, (short) 0, keyDerivationData,
                CHALLENGE_LENGTH, CHALLENGE_LENGTH);
        return keyDerivationData;
    }
    
    
    private class Mac {

    /**
     * The cipher used to encrypt the message and derive the MAC
     */
    private Cipher cipher;

    public Mac(SecretKey key)
            throws Exception {
        cipher = Cipher.getInstance("DES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0}));
    }

    /**
     * Checks the message signature.
     *
     * @param buffer
     *            The message buffer
     * @param offset
     *            The offset of the MAC in the buffer
     * @return true if the message signature is correct; false otherwise
     */
    protected boolean checkMAC(byte[] buffer, int offset) throws Exception {
        // Generate the MAC for the response
        byte[] paddedMsg = pad(buffer, 0, offset, cipher.getBlockSize());
        byte[] encryptedMsg = cipher.doFinal(paddedMsg);
        byte[] hostMAC =  new byte[MAC_LENGTH];
        System.arraycopy(encryptedMsg, encryptedMsg.length - MAC_LENGTH, hostMAC, 0, MAC_LENGTH);
        byte[] cardMAC = new byte[MAC_LENGTH];
        System.arraycopy(buffer, offset, cardMAC, 0, MAC_LENGTH);
        // Verify message signature
        return Arrays.equals(hostMAC, cardMAC);
    }

    /**
     * Generates a message MAC: generates the MAC and appends the MAC
     * to the message.
     *
     * @param buffer
     *            The APDU buffer
     * @param offset
     *            The offset of the MAC in the buffer
     * @return The resulting length of the request message
     * @throws Exception
     */
    protected short generateMAC(byte[] buffer, int offset)
            throws Exception {
        // Sign request message and append the MAC to the request message
        byte[] paddedMsg = pad(buffer, 0, offset, cipher.getBlockSize());
        byte[] encryptedMsg = cipher.doFinal(paddedMsg);
        System.arraycopy(encryptedMsg, encryptedMsg.length - MAC_LENGTH, buffer, offset, MAC_LENGTH);
        return (short) (offset + MAC_LENGTH);
    }
    }
}
