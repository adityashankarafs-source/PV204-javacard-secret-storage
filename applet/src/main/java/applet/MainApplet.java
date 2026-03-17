package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class MainApplet extends Applet implements Constants {

    private final OwnerPIN pin;
    private final SecretStore secretStore;

    private final byte[] masterKey;
    private final byte[] clientNonce;
    private final byte[] cardNonce;
    private final byte[] sessionKey;
    private final byte[] macBuffer;
    private final byte[] digestBuffer;

    private boolean secureChannelOpen;

    private final RandomData random;
    private final MessageDigest sha256;

    private MainApplet() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LEN);

        byte[] defaultPin = { '1', '2', '3', '4' };
        pin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        secretStore = new SecretStore();

        masterKey = new byte[] {
                0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, (byte) 0x88,
                0x21, 0x32, 0x43, 0x54,
                0x65, 0x76, 0x07, 0x18
        };

        clientNonce = new byte[NONCE_LEN];
        cardNonce = new byte[NONCE_LEN];
        sessionKey = new byte[SESSION_KEY_LEN];
        macBuffer = JCSystem.makeTransientByteArray(MAC_LEN, JCSystem.CLEAR_ON_DESELECT);
        digestBuffer = new byte[32];

        secureChannelOpen = false;

        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet();
    }

    public boolean select() {
        secureChannelOpen = false;
        pin.reset();
        return true;
    }

    public void deselect() {
        secureChannelOpen = false;
        pin.reset();
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

            case INS_OPEN_SECURE_CHANNEL:
                openSecureChannel(apdu);
                return;

            case INS_SECURE_VERIFY_PIN:
                requireSecureChannel();
                secureVerifyPin(apdu);
                return;

            case INS_SECURE_CHANGE_PIN:
                requireSecureChannel();
                secureChangePin(apdu);
                return;

            case INS_SECURE_STORE_SECRET:
                requireSecureChannel();
                secureStoreSecret(apdu);
                return;

            case INS_SECURE_GET_SECRET:
                requireSecureChannel();
                secureGetSecret(apdu);
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

    private void requireSecureChannel() {
        if (!secureChannelOpen) {
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
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

        changePinFromBuffer(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void storeSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        storeSecretFromBuffer(buffer, ISO7816.OFFSET_CDATA, len);
    }

    private void listSecrets(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short outLen = secretStore.list(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private void getSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short outLen = getSecretFromBuffer(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private void openSecureChannel(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (len != NONCE_LEN) {
            ISOException.throwIt(SW_INVALID_NONCE);
        }

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, clientNonce, (short) 0, NONCE_LEN);

        random.generateData(cardNonce, (short) 0, NONCE_LEN);
        deriveSessionKey();

        secureChannelOpen = true;

        Util.arrayCopy(cardNonce, (short) 0, buffer, (short) 0, NONCE_LEN);
        apdu.setOutgoingAndSend((short) 0, NONCE_LEN);
    }

    private void secureVerifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifySecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) payloadLen)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void secureChangePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifySecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        changePinFromBuffer(buffer, ISO7816.OFFSET_CDATA, payloadLen);
    }

    private void secureStoreSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifySecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        requirePin();
        storeSecretFromBuffer(buffer, ISO7816.OFFSET_CDATA, payloadLen);
    }

    private void secureGetSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifySecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        requirePin();
        short outLen = getSecretFromBuffer(buffer, ISO7816.OFFSET_CDATA, payloadLen, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, outLen);
    }

    private short verifySecurePayload(byte[] buffer, short dataOffset, short totalLen) {
        if (totalLen < MAC_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        short payloadLen = (short) (totalLen - MAC_LEN);
        short providedMacOffset = (short) (dataOffset + payloadLen);

        computeMac(buffer, dataOffset, payloadLen, macBuffer, (short) 0);

        if (Util.arrayCompare(buffer, providedMacOffset, macBuffer, (short) 0, MAC_LEN) != 0) {
            ISOException.throwIt(SW_INVALID_MAC);
        }

        return payloadLen;
    }

    private void deriveSessionKey() {
        short pos = 0;

        Util.arrayCopy(masterKey, (short) 0, digestBuffer, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;

        Util.arrayCopy(clientNonce, (short) 0, digestBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;

        Util.arrayCopy(cardNonce, (short) 0, digestBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;

        sha256.reset();
        sha256.doFinal(digestBuffer, (short) 0, pos, digestBuffer, (short) 0);

        Util.arrayCopy(digestBuffer, (short) 0, sessionKey, (short) 0, SESSION_KEY_LEN);
    }

    private void computeMac(byte[] data, short dataOffset, short dataLen, byte[] out, short outOffset) {
        short pos = 0;

        Util.arrayCopy(sessionKey, (short) 0, digestBuffer, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;

        Util.arrayCopy(data, dataOffset, digestBuffer, pos, dataLen);
        pos += dataLen;

        sha256.reset();
        sha256.doFinal(digestBuffer, (short) 0, pos, digestBuffer, (short) 0);

        Util.arrayCopy(digestBuffer, (short) 0, out, outOffset, MAC_LEN);
    }

    private void changePinFromBuffer(byte[] buffer, short offset, short len) {
        short pos = offset;
        short end = (short) (offset + len);

        if (len < 2) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        byte oldLen = buffer[pos++];
        if (oldLen < MIN_PIN_LEN || oldLen > MAX_PIN_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }
        if ((short) (pos + oldLen + 1) > end) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        if (!pin.check(buffer, pos, oldLen)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        pos += oldLen;

        byte newLen = buffer[pos++];
        if (newLen < MIN_PIN_LEN || newLen > MAX_PIN_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }
        if ((short) (pos + newLen) != end) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        pin.update(buffer, pos, newLen);
    }

    private void storeSecretFromBuffer(byte[] buffer, short offset, short len) {
        short pos = offset;
        short end = (short) (offset + len);

        if (len < 2) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        byte nameLen = buffer[pos++];
        if (nameLen <= 0 || nameLen > MAX_NAME_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }
        short nameOffset = pos;
        pos += nameLen;

        if (pos >= end) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        byte valueLen = buffer[pos++];
        if (valueLen < 0 || valueLen > MAX_VALUE_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }
        short valueOffset = pos;

        if ((short) (valueOffset + valueLen) != end) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        secretStore.store(buffer, nameOffset, nameLen, valueOffset, valueLen);
    }

    private short getSecretFromBuffer(byte[] buffer, short offset, short len, byte[] outBuffer, short outOffset) {
        short pos = offset;
        short end = (short) (offset + len);

        if (len < 1) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        byte nameLen = buffer[pos++];
        if (nameLen <= 0 || nameLen > MAX_NAME_LEN) {
            ISOException.throwIt(SW_INVALID_DATA);
        }
        if ((short) (pos + nameLen) != end) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        return secretStore.get(buffer, pos, nameLen, outBuffer, outOffset);
    }
}