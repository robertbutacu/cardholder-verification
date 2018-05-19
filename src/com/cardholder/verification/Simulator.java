package com.cardholder.verification;
import static com.cardholder.verification.Constants.*;
public class Simulator extends Terminal {

	public Simulator() throws Exception{
		super(DEFAULT_HOST_NAME, DEFAULT_PORT);
	}

    private void processEntry(short entryStationId) throws Exception {

        // Request Message: [2-bytes Entry Station ID]

        byte[] requestMessage = new byte[2];

        copyShort(entryStationId, requestMessage, 0);

        // Response Message: [[8-bytes UID], [2-bytes Correlation ID]]

        byte[] responseMessage = sendRequest(PROCESS_ENTRY, requestMessage);

        if (responseMessage != null) {

            // Retrieve the UID
            byte[] uid = new byte[UID_LENGTH];
            System.arraycopy(responseMessage, 0, uid, 0, UID_LENGTH);

            // Retrieve the correlation Id
            short correlationId = getShort(responseMessage, 2);

            System.out.println("processEntry: [" + entryStationId + "] => "
                    + "[ " + new String(uid) + ", " + correlationId + "]");
        } else {

            System.out.println("processEntry: [" + entryStationId + "] => "
                    + "error");
        }
    }

    /**
     * Sends a transit system exit event to the on-card applet for processing.
     *
     * @param transitFee
     *            The transit fee to be debited from the on-card account.
     * @throws Exception
     */
    private void processExit(byte transitFee) throws Exception {

        // Request Message: [1-byte Transit Fee]

        byte[] requestMessage = new byte[1];

        requestMessage[0] = transitFee;

        // Response Message: [[8-bytes UID], [2-bytes Correlation ID]]

        byte[] responseMessage = sendRequest(PROCESS_EXIT, requestMessage);

        if (responseMessage != null) {

            // Retrieve the UID
            byte[] uid = new byte[UID_LENGTH];
            System.arraycopy(responseMessage, 0, uid, 0, UID_LENGTH);

            // Retrieve the correlation Id
            short correlationId = getShort(responseMessage, 2);

            System.out.println("processEntry: [" + transitFee + "] => " + "[ "
                    + new String(uid) + ", " + correlationId + "]");
        } else {

            System.out.println("processEntry: [" + transitFee + "] => "
                    + "error");
        }
    }
}
