package com.cardholder.verification;

public final class Constants {
	 public static final byte CLA_ISO7816 = (byte) 0x00;

	 public static final byte TRANSIT_CLA = (byte) 0x80;

	 public static final  byte INS_VERIFY = (byte) 0x20;

	 public static final byte INS_SELECT = (byte) 0XA4;

	 public static final  byte INITIALIZE_SESSION = (byte) 0x30;

	 public static final  byte PROCESS_REQUEST = (byte) 0x40;

	 public static final  byte PROCESS_ENTRY = (byte) 0xC1;

	 public static final  byte PROCESS_EXIT = (byte) 0xC2;

	 public static final  byte CREDIT = (byte) 0xC3;
	 
	 public static final byte DEBIT = (byte) 0xC5;

	 public static final  byte GET_BALANCE = (byte) 0xC4;

     public static final int SW_NO_ERROR = (int) 0x9000;
 
	 public static final byte NO_CVM_REQUIRED = 0x1F;
	 
	 public static final byte PLAINTEXT_PIN_REQUIRED = 0x01;
	 
	 public static final byte ENCRYPTED_PIN_REQUIRED = 0x04;
	
	 public static final String DEFAULT_HOST_NAME = "localhost";
	
	 public static final int DEFAULT_PORT = 9025;
	 
	 public static final byte[] AID_TRANSIT = { (byte) 0xa0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
	            (byte) 0x62, (byte) 0x3, (byte) 0x1, (byte) 0xc, (byte) 0xD,
	            (byte) 0x1 };
	 
     public static final short MAC_LENGTH = (short) 8;
     
     public static short CHALLENGE_LENGTH = (short) 4;
     
     public static short LENGTH_DES_BYTE = (short) 8;
     
     public static short UID_LENGTH = (short) 8;


}
