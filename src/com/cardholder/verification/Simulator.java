package com.cardholder.verification;
import static com.cardholder.verification.Constants.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

public class Simulator extends Terminal {
	private final String PUBLIC_KEY_FILENAME = "E:\\Projects\\cardholder-verification\\src\\com\\cardholder\\verification\\public-key.txt";
	
	private RSAPublicKey publicKey;
	private Cipher cipher;
	private Account account;
	
	public Simulator() throws Exception{
		super(DEFAULT_HOST_NAME, DEFAULT_PORT);
		
        BufferedReader br = new BufferedReader(new FileReader(PUBLIC_KEY_FILENAME));
        String encodedPublicKey = br.readLine();
        publicKey = (RSAPublicKey) loadPublicKey(encodedPublicKey);

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        account.pin = new byte[4];
        
        account.pin[0] = 0;
        account.pin[1] = 0;
        account.pin[2] = 0;
        account.pin[3] = 0;
	}
}