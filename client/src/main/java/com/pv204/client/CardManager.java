package com.pv204.client;

public class CardManager {

    private String masterKey;

    public CardManager() {
        this.masterKey = System.getenv("MASTER_KEY");

        if (this.masterKey == null) {
            System.out.println("Warning: MASTER_KEY not set. Using default (insecure).");
            this.masterKey = "default-key";
        }
    }

    public void connect() {
        System.out.println("Connecting to card simulator...");
    }

    public void openSecureSession() {
        System.out.println("Opening secure session...");
        System.out.println("Exchanging nonces...");
        System.out.println("Deriving session key...");
        System.out.println("Secure session established (mock).");
    }

    public void sendCommand(String command) {
        System.out.println("Simulating command send: " + command);
    }
}