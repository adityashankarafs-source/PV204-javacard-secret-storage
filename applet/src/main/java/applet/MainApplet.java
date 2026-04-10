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
    private final byte[] workBuffer;

    private boolean secureChannelOpen;
    private boolean keyInitialized;
    private short expectedCounter;
    private short lastVerifiedCounter;

    private final RandomData random;
    private final MessageDigest sha256;

    private MainApplet() {
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LEN);
        byte[] defaultPin = { '1', '2', '3', '4' };
        pin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        secretStore = new SecretStore();

        masterKey = JCSystem.makeTransientByteArray(MASTER_KEY_LEN, JCSystem.CLEAR_ON_DESELECT);
        clientNonce = new byte[NONCE_LEN];
        cardNonce = new byte[NONCE_LEN];
        sessionKey = new byte[SESSION_KEY_LEN];
        macBuffer = JCSystem.makeTransientByteArray(MAC_LEN, JCSystem.CLEAR_ON_DESELECT);
        digestBuffer = new byte[SHA256_LEN];
        workBuffer = new byte[128];

        secureChannelOpen = false;
        keyInitialized = false;
        expectedCounter = 1;
        lastVerifiedCounter = 0;

        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MainApplet();
    }

    public boolean select() {
        resetSecurityState();
        return true;
    }

    public void deselect() {
        resetSecurityState();
    }

    private void resetSecurityState() {
        secureChannelOpen = false;
        expectedCounter = 1;
        lastVerifiedCounter = 0;
        pin.reset();

        Util.arrayFillNonAtomic(sessionKey, (short) 0, SESSION_KEY_LEN, (byte) 0);
        Util.arrayFillNonAtomic(clientNonce, (short) 0, NONCE_LEN, (byte) 0);
        Util.arrayFillNonAtomic(cardNonce, (short) 0, NONCE_LEN, (byte) 0);
        Util.arrayFillNonAtomic(masterKey, (short) 0, MASTER_KEY_LEN, (byte) 0);
        Util.arrayFillNonAtomic(macBuffer, (short) 0, MAC_LEN, (byte) 0);
        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);

        keyInitialized = false;
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
            case INS_INIT_MASTER_KEY:
                initMasterKey(apdu);
                return;

            case INS_OPEN_SECURE_CHANNEL:
                openSecureChannel(apdu);
                return;

            case INS_VERIFY_PIN:
            case INS_CHANGE_PIN:
            case INS_STORE_SECRET:
            case INS_LIST_SECRETS:
            case INS_GET_SECRET:
                ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
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

            case INS_SECURE_LIST_SECRETS:
                requireSecureChannel();
                secureListSecrets(apdu);
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

    private void requireProvisionedKey() {
        if (!keyInitialized) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    private void initMasterKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        if (len != MASTER_KEY_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, masterKey, (short) 0, MASTER_KEY_LEN);
        keyInitialized = true;
        secureChannelOpen = false;
        expectedCounter = 1;
        lastVerifiedCounter = 0;

        Util.arrayFillNonAtomic(sessionKey, (short) 0, SESSION_KEY_LEN, (byte) 0);
        Util.arrayFillNonAtomic(clientNonce, (short) 0, NONCE_LEN, (byte) 0);
        Util.arrayFillNonAtomic(cardNonce, (short) 0, NONCE_LEN, (byte) 0);
    }

    private void openSecureChannel(APDU apdu) {
        requireProvisionedKey();

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        if (len != NONCE_LEN) {
            ISOException.throwIt(SW_INVALID_NONCE);
        }

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, clientNonce, (short) 0, NONCE_LEN);
        random.generateData(cardNonce, (short) 0, NONCE_LEN);
        deriveSessionKey();

        secureChannelOpen = true;
        expectedCounter = 1;
        lastVerifiedCounter = 0;

        Util.arrayCopy(cardNonce, (short) 0, buffer, (short) 0, NONCE_LEN);
        computeHandshakeProof(buffer, (short) NONCE_LEN);
        apdu.setOutgoingAndSend((short) 0, (short) (NONCE_LEN + MAC_LEN));
    }

    private void secureVerifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifyAndDecryptSecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + COUNTER_LEN), (byte) payloadLen)) {
            wipeSecurePayloadArea(buffer, totalLen);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        wipeSecurePayloadArea(buffer, totalLen);
    }

    private void secureChangePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifyAndDecryptSecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        changePinFromBuffer(buffer, (short) (ISO7816.OFFSET_CDATA + COUNTER_LEN), payloadLen);
        wipeSecurePayloadArea(buffer, totalLen);
    }

    private void secureStoreSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifyAndDecryptSecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        requirePin();
        storeSecretFromBuffer(buffer, (short) (ISO7816.OFFSET_CDATA + COUNTER_LEN), payloadLen);
        wipeSecurePayloadArea(buffer, totalLen);
    }

    private void secureGetSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        short payloadLen = verifyAndDecryptSecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        requirePin();

        short plainLen = getSecretFromBuffer(
                buffer,
                (short) (ISO7816.OFFSET_CDATA + COUNTER_LEN),
                payloadLen,
                workBuffer,
                (short) 0
        );

        wipeSecurePayloadArea(buffer, totalLen);

        short responseLen = buildSecureResponse(workBuffer, (short) 0, plainLen, buffer, (short) 0);

        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);

        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    private void secureListSecrets(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short totalLen = apdu.setIncomingAndReceive();
        verifyAndDecryptSecurePayload(buffer, ISO7816.OFFSET_CDATA, totalLen);

        requirePin();

        short plainLen = secretStore.list(workBuffer, (short) 0);

        wipeSecurePayloadArea(buffer, totalLen);

        short responseLen = buildSecureResponse(workBuffer, (short) 0, plainLen, buffer, (short) 0);

        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);

        apdu.setOutgoingAndSend((short) 0, responseLen);
    }

    private short verifyAndDecryptSecurePayload(byte[] buffer, short dataOffset, short totalLen) {
        if (totalLen < (short) (COUNTER_LEN + MAC_LEN)) {
            ISOException.throwIt(SW_INVALID_DATA);
        }

        short counter = Util.getShort(buffer, dataOffset);
        if (counter != expectedCounter) {
            ISOException.throwIt(SW_REPLAY_DETECTED);
        }

        short cipherOffset = (short) (dataOffset + COUNTER_LEN);
        short cipherLen = (short) (totalLen - COUNTER_LEN - MAC_LEN);
        short providedMacOffset = (short) (cipherOffset + cipherLen);

        computeMacWithIns(
                buffer,
                dataOffset,
                (short) (COUNTER_LEN + cipherLen),
                DIRECTION_REQUEST,
                buffer[ISO7816.OFFSET_INS],
                macBuffer,
                (short) 0
        );

        if (Util.arrayCompare(buffer, providedMacOffset, macBuffer, (short) 0, MAC_LEN) != 0) {
            ISOException.throwIt(SW_INVALID_MAC);
        }

        cryptInPlace(buffer, cipherOffset, cipherLen, counter, DIRECTION_REQUEST);
        lastVerifiedCounter = counter;
        expectedCounter++;
        return cipherLen;
    }

    private short buildSecureResponse(byte[] plain, short plainOffset, short plainLen, byte[] out, short outOffset) {
        Util.setShort(out, outOffset, lastVerifiedCounter);

        short cipherOffset = (short) (outOffset + COUNTER_LEN);
        Util.arrayCopy(plain, plainOffset, out, cipherOffset, plainLen);
        cryptInPlace(out, cipherOffset, plainLen, lastVerifiedCounter, DIRECTION_RESPONSE);

        short macOffset = (short) (cipherOffset + plainLen);
        computeMacWithIns(
                out,
                outOffset,
                (short) (COUNTER_LEN + plainLen),
                DIRECTION_RESPONSE,
                (byte) 0x00,
                out,
                macOffset
        );

        return (short) (COUNTER_LEN + plainLen + MAC_LEN);
    }

    private void deriveSessionKey() {
        short pos = 0;

        Util.arrayCopy(masterKey, (short) 0, workBuffer, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        Util.arrayCopy(clientNonce, (short) 0, workBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;
        Util.arrayCopy(cardNonce, (short) 0, workBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;
        workBuffer[pos++] = (byte) 0x11;

        sha256.reset();
        sha256.doFinal(workBuffer, (short) 0, pos, digestBuffer, (short) 0);
        Util.arrayCopy(digestBuffer, (short) 0, sessionKey, (short) 0, SESSION_KEY_LEN);

        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);
        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
    }

    private void computeHandshakeProof(byte[] out, short outOffset) {
        short pos = 0;

        Util.arrayCopy(masterKey, (short) 0, workBuffer, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        Util.arrayCopy(clientNonce, (short) 0, workBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;
        Util.arrayCopy(cardNonce, (short) 0, workBuffer, pos, NONCE_LEN);
        pos += NONCE_LEN;
        workBuffer[pos++] = (byte) 0x7A;

        sha256.reset();
        sha256.doFinal(workBuffer, (short) 0, pos, digestBuffer, (short) 0);
        Util.arrayCopy(digestBuffer, (short) 0, out, outOffset, MAC_LEN);

        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);
        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
    }

    private void computeMacWithIns(byte[] data, short dataOffset, short dataLen, byte direction, byte ins, byte[] out, short outOffset) {
        short pos = 0;

        Util.arrayCopy(sessionKey, (short) 0, workBuffer, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        workBuffer[pos++] = direction;
        workBuffer[pos++] = ins;
        Util.setShort(workBuffer, pos, dataLen);
        pos += 2;
        Util.arrayCopy(data, dataOffset, workBuffer, pos, dataLen);
        pos += dataLen;

        sha256.reset();
        sha256.doFinal(workBuffer, (short) 0, pos, digestBuffer, (short) 0);
        Util.arrayCopy(digestBuffer, (short) 0, out, outOffset, MAC_LEN);

        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);
        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
    }

    private void cryptInPlace(byte[] data, short offset, short len, short counter, byte direction) {
        short processed = 0;
        short blockIndex = 0;

        while (processed < len) {
            short streamLen = generateKeystream(counter, blockIndex, direction);
            short chunk = (short) (len - processed);
            if (chunk > streamLen) {
                chunk = streamLen;
            }

            short i;
            for (i = 0; i < chunk; i++) {
                short position = (short) (offset + processed + i);
                data[position] ^= digestBuffer[i];
            }

            processed += chunk;
            blockIndex++;
        }

        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
    }

    private short generateKeystream(short counter, short blockIndex, byte direction) {
        short pos = 0;

        Util.arrayCopy(sessionKey, (short) 0, workBuffer, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        Util.setShort(workBuffer, pos, counter);
        pos += 2;
        Util.setShort(workBuffer, pos, blockIndex);
        pos += 2;
        workBuffer[pos++] = direction;
        workBuffer[pos++] = (byte) 0x22;

        sha256.reset();
        sha256.doFinal(workBuffer, (short) 0, pos, digestBuffer, (short) 0);
        Util.arrayFillNonAtomic(workBuffer, (short) 0, (short) workBuffer.length, (byte) 0);
        return SHA256_LEN;
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

    private void wipeSecurePayloadArea(byte[] buffer, short totalLen) {
        if (totalLen > 0) {
            Util.arrayFillNonAtomic(buffer, ISO7816.OFFSET_CDATA, totalLen, (byte) 0);
        }
        Util.arrayFillNonAtomic(macBuffer, (short) 0, MAC_LEN, (byte) 0);
        Util.arrayFillNonAtomic(digestBuffer, (short) 0, SHA256_LEN, (byte) 0);
    }
}