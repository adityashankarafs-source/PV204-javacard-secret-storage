package com.pv204.client;

public class CardManager {

    public void connect() {
        System.out.println("Connecting to card simulator...");
    }

    public void sendCommand(String command) {
        System.out.println("Simulating command send: " + command);
    }
}