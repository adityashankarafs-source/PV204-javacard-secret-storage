package com.pv204.client;

public class CardManager {
    private final String masterKey;

    public CardManager() {
        this.masterKey = System.getenv("MASTER_KEY");
        if (this.masterKey == null || this.masterKey.trim().isEmpty()) {
            throw new IllegalStateException("MASTER_KEY not set");
        }
    }

    public void connect() {
        System.out.println("Connecting to card simulator...");
    }

    public void openSecureSession() {
        System.out.println("Opening secure session...");
        System.out.println("Exchanging nonces...");
        System.out.println("Deriving session key...");
        System.out.println("Secure session established.");
    }

    public void sendCommand(String command) {
        System.out.println("Simulating command send: " + command);
    }
}