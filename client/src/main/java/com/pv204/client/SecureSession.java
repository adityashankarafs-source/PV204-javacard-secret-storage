package com.pv204.client;

import applet.Constants;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SecureSession {
    private final ApduTransport transport;
    private final SecureRandom random = new SecureRandom();

    private byte[] masterKey;
    private byte[] clientNonce;
    private byte[] cardNonce;
    private byte[] sessionKey;
    private short counter;
    private boolean open;

    public SecureSession(ApduTransport transport) {
        this.transport = transport;
        this.counter = 1;
        this.open = false;
    }

    public void initMasterKey(byte[] key) throws Exception {
        if (key == null || key.length != Constants.MASTER_KEY_LEN) {
            throw new IllegalArgumentException("Master key must be exactly 16 bytes");
        }

        ResponseAPDU response = transport.transmit(
                new CommandAPDU(Constants.APPLET_CLA, Constants.INS_INIT_MASTER_KEY, 0x00, 0x00, key)
        );
        ensureSuccess(response, "INIT_MASTER_KEY failed");

        this.masterKey = Arrays.copyOf(key, key.length);
        this.sessionKey = null;
        this.clientNonce = null;
        this.cardNonce = null;
        this.counter = 1;
        this.open = false;
    }

    public void openSecureChannel() throws Exception {
        if (masterKey == null) {
            throw new IllegalStateException("Initialize master key first using: init <key>");
        }

        clientNonce = new byte[Constants.NONCE_LEN];
        random.nextBytes(clientNonce);

        ResponseAPDU response = transport.transmit(
                new CommandAPDU(Constants.APPLET_CLA, Constants.INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, clientNonce)
        );
        ensureSuccess(response, "OPEN_SECURE_CHANNEL failed");

        byte[] data = response.getData();
        if (data.length != Constants.NONCE_LEN + Constants.MAC_LEN) {
            throw new IllegalStateException("Invalid secure-channel response length");
        }

        cardNonce = Arrays.copyOfRange(data, 0, Constants.NONCE_LEN);
        byte[] proof = Arrays.copyOfRange(data, Constants.NONCE_LEN, Constants.NONCE_LEN + Constants.MAC_LEN);

        sessionKey = deriveSessionKey(masterKey, clientNonce, cardNonce);
        byte[] expectedProof = computeHandshakeProof(masterKey, clientNonce, cardNonce);

        if (!Arrays.equals(proof, expectedProof)) {
            throw new IllegalStateException("Handshake proof verification failed");
        }

        counter = 1;
        open = true;
    }

    public void secureVerifyPin(String pin) throws Exception {
        ensureOpen();
        ResponseAPDU response = transmitSecure(Constants.INS_SECURE_VERIFY_PIN, pin.getBytes(), false);
        ensureSuccess(response, "PIN verification failed");
    }

    public void secureStore(String name, String value) throws Exception {
        ensureOpen();
        byte[] payload = encodeNameValue(name, value);
        ResponseAPDU response = transmitSecure(Constants.INS_SECURE_STORE_SECRET, payload, false);
        ensureSuccess(response, "Store failed");
    }

    public List<String> secureList() throws Exception {
        ensureOpen();
        ResponseAPDU response = transmitSecure(Constants.INS_SECURE_LIST_SECRETS, new byte[0], true);
        ensureSuccess(response, "List failed");

        byte[] plain = decryptSecureResponse(response.getData());
        return decodeNameList(plain);
    }

    public String secureGet(String name) throws Exception {
        ensureOpen();
        byte[] payload = encodeName(name);
        ResponseAPDU response = transmitSecure(Constants.INS_SECURE_GET_SECRET, payload, true);
        ensureSuccess(response, "Get failed");

        byte[] plain = decryptSecureResponse(response.getData());
        return new String(plain);
    }

    public void secureChangePin(String oldPin, String newPin) throws Exception {
        ensureOpen();
        byte[] payload = encodeChangePin(oldPin, newPin);
        ResponseAPDU response = transmitSecure(Constants.INS_SECURE_CHANGE_PIN, payload, false);
        ensureSuccess(response, "Change PIN failed");
    }

    private ResponseAPDU transmitSecure(byte ins, byte[] plainPayload, boolean expectEncryptedResponse) throws Exception {
        byte[] encrypted = Arrays.copyOf(plainPayload, plainPayload.length);
        cryptInPlace(encrypted, counter, (short) 0, Constants.DIRECTION_REQUEST);

        byte[] body = new byte[Constants.COUNTER_LEN + encrypted.length];
        putShort(body, 0, counter);
        System.arraycopy(encrypted, 0, body, Constants.COUNTER_LEN, encrypted.length);

        byte[] mac = computeMac(body, Constants.DIRECTION_REQUEST, ins);

        byte[] full = new byte[body.length + Constants.MAC_LEN];
        System.arraycopy(body, 0, full, 0, body.length);
        System.arraycopy(mac, 0, full, body.length, Constants.MAC_LEN);

        ResponseAPDU response = transport.transmit(
                new CommandAPDU(Constants.APPLET_CLA, ins, 0x00, 0x00, full)
        );

        counter++;
        return response;
    }

    private byte[] decryptSecureResponse(byte[] responseData) throws Exception {
        if (responseData.length < Constants.COUNTER_LEN + Constants.MAC_LEN) {
            throw new IllegalStateException("Invalid encrypted response");
        }

        short respCounter = getShort(responseData, 0);
        int cipherLen = responseData.length - Constants.COUNTER_LEN - Constants.MAC_LEN;

        byte[] body = Arrays.copyOfRange(responseData, 0, Constants.COUNTER_LEN + cipherLen);
        byte[] mac = Arrays.copyOfRange(responseData, Constants.COUNTER_LEN + cipherLen, responseData.length);

        byte[] expectedMac = computeMac(body, Constants.DIRECTION_RESPONSE, (byte) 0x00);
        if (!Arrays.equals(expectedMac, mac)) {
            throw new IllegalStateException("Invalid response MAC");
        }

        byte[] cipher = Arrays.copyOfRange(responseData, Constants.COUNTER_LEN, Constants.COUNTER_LEN + cipherLen);
        cryptInPlace(cipher, respCounter, (short) 0, Constants.DIRECTION_RESPONSE);
        return cipher;
    }

    private byte[] deriveSessionKey(byte[] mk, byte[] cNonce, byte[] sNonce) throws Exception {
        byte[] input = new byte[Constants.MASTER_KEY_LEN + Constants.NONCE_LEN + Constants.NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(mk, 0, input, pos, Constants.MASTER_KEY_LEN);
        pos += Constants.MASTER_KEY_LEN;
        System.arraycopy(cNonce, 0, input, pos, Constants.NONCE_LEN);
        pos += Constants.NONCE_LEN;
        System.arraycopy(sNonce, 0, input, pos, Constants.NONCE_LEN);
        pos += Constants.NONCE_LEN;
        input[pos] = (byte) 0x11;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, Constants.SESSION_KEY_LEN);
    }

    private byte[] computeHandshakeProof(byte[] mk, byte[] cNonce, byte[] sNonce) throws Exception {
        byte[] input = new byte[Constants.MASTER_KEY_LEN + Constants.NONCE_LEN + Constants.NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(mk, 0, input, pos, Constants.MASTER_KEY_LEN);
        pos += Constants.MASTER_KEY_LEN;
        System.arraycopy(cNonce, 0, input, pos, Constants.NONCE_LEN);
        pos += Constants.NONCE_LEN;
        System.arraycopy(sNonce, 0, input, pos, Constants.NONCE_LEN);
        pos += Constants.NONCE_LEN;
        input[pos] = (byte) 0x7A;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, Constants.MAC_LEN);
    }

    private byte[] computeMac(byte[] data, byte direction, byte ins) throws Exception {
        byte[] input = new byte[Constants.SESSION_KEY_LEN + 1 + 1 + 2 + data.length];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, Constants.SESSION_KEY_LEN);
        pos += Constants.SESSION_KEY_LEN;
        input[pos++] = direction;
        input[pos++] = ins;
        putShort(input, pos, (short) data.length);
        pos += 2;
        System.arraycopy(data, 0, input, pos, data.length);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, Constants.MAC_LEN);
    }

    private void cryptInPlace(byte[] data, short msgCounter, short initialBlockIndex, byte direction) throws Exception {
        int processed = 0;
        short blockIndex = initialBlockIndex;

        while (processed < data.length) {
            byte[] stream = generateKeystream(msgCounter, blockIndex, direction);
            int chunk = Math.min(stream.length, data.length - processed);

            for (int i = 0; i < chunk; i++) {
                data[processed + i] ^= stream[i];
            }

            processed += chunk;
            blockIndex++;
        }
    }

    private byte[] generateKeystream(short msgCounter, short blockIndex, byte direction) throws Exception {
        byte[] input = new byte[Constants.SESSION_KEY_LEN + 2 + 2 + 1 + 1];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, Constants.SESSION_KEY_LEN);
        pos += Constants.SESSION_KEY_LEN;
        putShort(input, pos, msgCounter);
        pos += 2;
        putShort(input, pos, blockIndex);
        pos += 2;
        input[pos++] = direction;
        input[pos] = (byte) 0x22;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }

    private List<String> decodeNameList(byte[] data) {
        List<String> names = new ArrayList<>();
        int pos = 0;

        while (pos < data.length) {
            int len = data[pos] & 0xFF;
            pos++;
            if (len == 0 || pos + len > data.length) {
                break;
            }
            names.add(new String(data, pos, len));
            pos += len;
        }

        return names;
    }

    private byte[] encodeName(String name) {
        byte[] nameBytes = name.getBytes();
        byte[] out = new byte[1 + nameBytes.length];
        out[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, 1, nameBytes.length);
        return out;
    }

    private byte[] encodeNameValue(String name, String value) {
        byte[] nameBytes = name.getBytes();
        byte[] valueBytes = value.getBytes();
        byte[] out = new byte[1 + nameBytes.length + 1 + valueBytes.length];

        int pos = 0;
        out[pos++] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, pos, nameBytes.length);
        pos += nameBytes.length;
        out[pos++] = (byte) valueBytes.length;
        System.arraycopy(valueBytes, 0, out, pos, valueBytes.length);

        return out;
    }

    private byte[] encodeChangePin(String oldPin, String newPin) {
        byte[] oldBytes = oldPin.getBytes();
        byte[] newBytes = newPin.getBytes();
        byte[] out = new byte[1 + oldBytes.length + 1 + newBytes.length];

        int pos = 0;
        out[pos++] = (byte) oldBytes.length;
        System.arraycopy(oldBytes, 0, out, pos, oldBytes.length);
        pos += oldBytes.length;
        out[pos++] = (byte) newBytes.length;
        System.arraycopy(newBytes, 0, out, pos, newBytes.length);

        return out;
    }

    private void ensureOpen() {
        if (!open || sessionKey == null) {
            throw new IllegalStateException("Open secure channel first using: open");
        }
    }

    private void ensureSuccess(ResponseAPDU response, String message) {
        if (response.getSW() != 0x9000) {
            throw new IllegalStateException(message + " (SW=" + Integer.toHexString(response.getSW()) + ")");
        }
    }

    private void putShort(byte[] buffer, int offset, short value) {
        buffer[offset] = (byte) ((value >> 8) & 0xFF);
        buffer[offset + 1] = (byte) (value & 0xFF);
    }

    private short getShort(byte[] buffer, int offset) {
        return (short) (((buffer[offset] & 0xFF) << 8) | (buffer[offset + 1] & 0xFF));
    }
}