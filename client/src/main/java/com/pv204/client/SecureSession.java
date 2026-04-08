package com.pv204.client;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SecureSession implements ProtocolConstants {
    private final ApduTransport transport;
    private final SecureRandom secureRandom = new SecureRandom();

    private byte[] sessionKey;
    private short nextCounter = 1;
    private boolean open;

    public SecureSession(ApduTransport transport) {
        this.transport = transport;
    }

    public void verifyPin(String pin) {
        ensureOpen();
        sendSecureCommand(INS_SECURE_VERIFY_PIN, pin.getBytes(StandardCharsets.UTF_8), false);
    }

    public void changePin(String oldPin, String newPin) {
        ensureOpen();
        byte[] oldBytes = oldPin.getBytes(StandardCharsets.UTF_8);
        byte[] newBytes = newPin.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[2 + oldBytes.length + newBytes.length];
        int pos = 0;
        payload[pos++] = (byte) oldBytes.length;
        System.arraycopy(oldBytes, 0, payload, pos, oldBytes.length);
        pos += oldBytes.length;
        payload[pos++] = (byte) newBytes.length;
        System.arraycopy(newBytes, 0, payload, pos, newBytes.length);
        sendSecureCommand(INS_SECURE_CHANGE_PIN, payload, false);
    }

    public void storeSecret(String name, String value) {
        ensureOpen();
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[2 + nameBytes.length + valueBytes.length];
        int pos = 0;
        payload[pos++] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, payload, pos, nameBytes.length);
        pos += nameBytes.length;
        payload[pos++] = (byte) valueBytes.length;
        System.arraycopy(valueBytes, 0, payload, pos, valueBytes.length);
        sendSecureCommand(INS_SECURE_STORE_SECRET, payload, false);
    }

    public String getSecret(String name) {
        ensureOpen();
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[1 + nameBytes.length];
        payload[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, payload, 1, nameBytes.length);
        byte[] plain = sendSecureCommand(INS_SECURE_GET_SECRET, payload, true);
        return new String(plain, StandardCharsets.UTF_8);
    }

    public List<String> listSecrets() {
        ensureOpen();
        byte[] plain = sendSecureCommand(INS_SECURE_LIST_SECRETS, new byte[0], true);
        List<String> names = new ArrayList<>();
        int pos = 0;
        while (pos < plain.length) {
            int len = plain[pos++] & 0xFF;
            names.add(new String(plain, pos, len, StandardCharsets.UTF_8));
            pos += len;
        }
        return names;
    }

    private void ensureOpen() {
        if (open) {
            return;
        }

        byte[] clientNonce = new byte[NONCE_LEN];
        secureRandom.nextBytes(clientNonce);

        TransportResponse response = transport.transmit(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, (byte) 0x00, (byte) 0x00, clientNonce);
        assertSw(response.getSw());

        byte[] responseData = response.getData();
        if (responseData.length != NONCE_LEN + MAC_LEN) {
            throw new IllegalStateException("Invalid secure-channel handshake response length");
        }

        byte[] cardNonce = Arrays.copyOfRange(responseData, 0, NONCE_LEN);
        byte[] proof = Arrays.copyOfRange(responseData, NONCE_LEN, NONCE_LEN + MAC_LEN);
        byte[] expectedProof = CryptoUtil.computeHandshakeProof(clientNonce, cardNonce);
        if (!Arrays.equals(proof, expectedProof)) {
            throw new IllegalStateException("Card handshake proof verification failed");
        }

        sessionKey = CryptoUtil.deriveSessionKey(clientNonce, cardNonce);
        open = true;
        nextCounter = 1;
    }

    private byte[] sendSecureCommand(byte ins, byte[] plainPayload, boolean expectProtectedResponse) {
        short counter = nextCounter;
        byte[] cipherPayload = CryptoUtil.crypt(sessionKey, counter, DIRECTION_REQUEST, plainPayload);
        byte[] mac = CryptoUtil.computeMac(sessionKey, counter, DIRECTION_REQUEST, cipherPayload);
        byte[] requestData = CryptoUtil.concat(CryptoUtil.shortToBytes(counter), cipherPayload, mac);

        TransportResponse response = transport.transmit(APPLET_CLA, ins, (byte) 0x00, (byte) 0x00, requestData);
        assertSw(response.getSw());
        nextCounter++;

        if (!expectProtectedResponse) {
            return new byte[0];
        }

        byte[] responseData = response.getData();
        if (responseData.length < COUNTER_LEN + MAC_LEN) {
            throw new IllegalStateException("Protected response too short");
        }

        short responseCounter = CryptoUtil.bytesToShort(responseData, 0);
        if (responseCounter != counter) {
            throw new IllegalStateException("Response counter mismatch");
        }

        byte[] cipher = Arrays.copyOfRange(responseData, COUNTER_LEN, responseData.length - MAC_LEN);
        byte[] providedMac = Arrays.copyOfRange(responseData, responseData.length - MAC_LEN, responseData.length);
        byte[] expectedMac = CryptoUtil.computeMac(sessionKey, responseCounter, DIRECTION_RESPONSE, cipher);
        if (!Arrays.equals(providedMac, expectedMac)) {
            throw new IllegalStateException("Protected response MAC verification failed");
        }

        return CryptoUtil.crypt(sessionKey, responseCounter, DIRECTION_RESPONSE, cipher);
    }

    private void assertSw(int sw) {
        if (sw == SW_OK) {
            return;
        }
        throw new IllegalStateException("Card returned status word 0x" + Integer.toHexString(sw).toUpperCase());
    }
}
