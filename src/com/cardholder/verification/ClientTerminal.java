package com.cardholder.verification;

import static com.cardholder.verification.Constants.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ClientTerminal extends Terminal {
	private boolean isValidated = false;
	
	public ClientTerminal() throws Exception {
		super(Constants.DEFAULT_HOST_NAME, Constants.DEFAULT_PORT);
	}

	public void start() {
        while (true) {
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

                System.out.println("Insert PIN: ");
                String PIN = br.readLine();

                boolean valid = true;
                for (int i = 0; i < PIN.length(); ++i) {
                    if (PIN.charAt(i) < '0' || PIN.charAt(i) > '9') {
                        System.out.println("Invalid PIN: " + PIN);
                        valid = false;
                        break;
                    }
                }
                if (!valid) {
                    continue;
                }

                System.out.println("Insert method (balance/credit/debit): ");
                String method = br.readLine().toLowerCase();
                short amount = 0;

                switch (method.toLowerCase()) {
                    case "balance":
                        getBalance(PIN);
                        break;

                    case "credit":
                    	System.out.println("Insert amount to credit");
                    	amount = Short.parseShort(br.readLine());
                        credit(PIN, amount);
                        break;

                    case "debit":
                    	System.out.println("Insert amount to debit");
                    	amount = Short.parseShort(br.readLine());
                        debit(PIN, amount);
                        break;

                    default:
                        System.out.println("Invalid command: " + method);
                        continue;
                }


            } catch (Exception e) {
                System.out.println(e.getMessage());
            }

        }
    }
    private void getBalance(String pin) throws Exception {

        // Request Message: []

        byte[] requestMessage = new byte[0];

        // Response Message: [2-bytes Balance]

        byte[] responseMessage = sendRequest(GET_BALANCE, requestMessage);

        if (responseMessage != null) {

            // Retrieve the balance
            short balance = getShort(responseMessage, 0);

            System.out.println("getBalance: [] => " + "[ " + balance + " ]");
        } else {

            System.out.println("getBalance: [] => " + "error");
        }
    }

    private void credit(String pin, short amount) throws Exception {

        // Request Message: [1-byte Credit Amount]

        byte[] requestMessage = new byte[10];
        
        requestMessage[0] = 2;
        copyShort(amount, requestMessage, 1);

        // Response Message: []

        byte[] responseMessage = sendRequest(CREDIT, requestMessage);

        if (responseMessage != null) {

            System.out.println("credit: [" + amount + "] => " + "OK");
        } else {

            System.out.println("credit: [" + amount + "] => " + "error");
        }
    }

    private String encryptPin(String pin) {
		// TODO Auto-generated method stub
		return pin;
	}

	private void debit(String pin, short amount) throws Exception {
        byte[] requestMessage = new byte[10];
      
        copyShort(amount, requestMessage, 1);

        if(amount > 50 && amount < 100) {
        	System.arraycopy(requestMessage, 3, pin, 0, pin.length());
            requestMessage[0] = (byte) (2 + pin.length());
        }
        else if(amount > 100) {
        	String encryptedPin = encryptPin(pin);
        	System.arraycopy(requestMessage, 3, encryptedPin, 0, pin.length());
            requestMessage[0] = (byte) (2 + encryptedPin.length());
        } else {
            requestMessage[0] = (byte) 2;
        }
    	
        byte[] responseMessage = sendRequest(DEBIT, requestMessage);
        
        if (responseMessage != null) {

            System.out.println("debited: [" + amount + "] => " + "OK");
        } else {
            System.out.println("debited: [" + amount + "] => " + "error");
        }

    }

    public static void main(String[] args) throws Exception {

        ClientTerminal terminal = new ClientTerminal();

        terminal.powerUp();
        terminal.selectApplet();
        terminal.initializeSession();
        
        terminal.powerDown();

        System.exit(0);
    }
    
    
}
