package com.pv204.client;

import java.util.List;

public class CardManager {
    private final ApduTransport transport;
    private final SecureSession secureSession;

    public CardManager() throws Exception {
        this.transport = new JCardSimTransport();
        this.transport.connect();
        this.secureSession = new SecureSession(transport);
    }

    public String init(String keyInput) throws Exception {
        byte[] key = parseKey(keyInput);
        secureSession.initMasterKey(key);
        return "Master key initialized.";
    }

    public String open() throws Exception {
        secureSession.openSecureChannel();
        return "Secure channel opened.";
    }

    public String verify(String pin) throws Exception {
        secureSession.secureVerifyPin(pin);
        return "PIN verified.";
    }

    public String store(String name, String value) throws Exception {
        secureSession.secureStore(name, value);
        return "Secret stored: " + name;
    }

    public List<String> list() throws Exception {
        return secureSession.secureList();
    }

    public String get(String name) throws Exception {
        return secureSession.secureGet(name);
    }

    public String changePin(String oldPin, String newPin) throws Exception {
        secureSession.secureChangePin(oldPin, newPin);
        return "PIN changed successfully.";
    }

    private byte[] parseKey(String keyInput) {
        if (keyInput == null) {
            throw new IllegalArgumentException("Key is required");
        }

        String trimmed = keyInput.trim();

        if (trimmed.matches("(?i)[0-9a-f]{32}")) {
            byte[] out = new byte[16];
            for (int i = 0; i < 16; i++) {
                out[i] = (byte) Integer.parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }

        byte[] ascii = trimmed.getBytes();
        if (ascii.length == 16) {
            return ascii;
        }

        throw new IllegalArgumentException("Key must be either 32 hex chars or exactly 16 ASCII chars");
    }
}