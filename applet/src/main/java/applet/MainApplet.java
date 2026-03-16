package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class MainApplet extends Applet implements Constants {

    private OwnerPIN pin;
    private SecretStore secretStore;

    private MainApplet() {

        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LEN);

        byte[] defaultPin = { '1', '2', '3', '4' };
        pin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        secretStore = new SecretStore();

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet();
    }

    public void process(APDU apdu) {

        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != APPLET_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {

            case INS_VERIFY_PIN:
                verifyPin(apdu);
                return;

            case INS_CHANGE_PIN:
                changePin(apdu);
                return;

            case INS_STORE_SECRET:
                requirePin();
                storeSecret(apdu);
                return;

            case INS_LIST_SECRETS:
                listSecrets(apdu);
                return;

            case INS_GET_SECRET:
                requirePin();
                getSecret(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void requirePin() {
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_REQUIRED);
        }
    }

    private void verifyPin(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) len)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void changePin(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short pos = ISO7816.OFFSET_CDATA;

        byte oldLen = buffer[pos++];
        if (!pin.check(buffer, pos, oldLen)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        pos += oldLen;

        byte newLen = buffer[pos++];
        pin.update(buffer, pos, newLen);
    }

    private void storeSecret(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short pos = ISO7816.OFFSET_CDATA;

        byte nameLen = buffer[pos++];
        short nameOffset = pos;

        pos += nameLen;

        byte valueLen = buffer[pos++];
        short valueOffset = pos;

        secretStore.store(buffer, nameOffset, nameLen, valueOffset, valueLen);
    }

    private void listSecrets(APDU apdu) {

        byte[] buffer = apdu.getBuffer();

        short outLen = secretStore.list(buffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private void getSecret(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short pos = ISO7816.OFFSET_CDATA;

        byte nameLen = buffer[pos++];
        short nameOffset = pos;

        short outLen = secretStore.get(buffer, nameOffset, nameLen, buffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, outLen);
    }
}