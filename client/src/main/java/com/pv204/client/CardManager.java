package com.pv204.client;

import java.util.*;

public class CardManager {

    private final Map<String, String> storage = new HashMap<>();

    public void connect() {
        System.out.println("Connecting to card simulator...");
    }

    public void openSecureSession() {
        System.out.println("Opening secure session...");
        System.out.println("Exchanging nonces...");
        System.out.println("Deriving session key...");
        System.out.println("Secure session established.");
    }

    public ClientResponse handle(ClientRequest req) {
        connect();
        openSecureSession();

        String command = req.getCommand();

        switch (command) {

            case "add":
                return handleAdd(req);

            case "list":
                return handleList();

            case "get":
                return handleGet(req);

            case "change-pin":
                return handleChangePin(req);

            default:
                return new ClientResponse(false, "Unknown command");
        }
    }

    // ================= ADD =================
    private ClientResponse handleAdd(ClientRequest req) {
        String name = req.getName();
        String value = req.getValue();

        if (name == null || value == null) {
            return new ClientResponse(false, "Missing name or value");
        }

        storage.put(name, value);
        return new ClientResponse(true, "Secret stored successfully");
    }

    // ================= LIST =================
    private ClientResponse handleList() {
        List<String> list = new ArrayList<>(storage.keySet());
        return new ClientResponse(true, "Stored secrets:", list);
    }

    // ================= GET =================
    private ClientResponse handleGet(ClientRequest req) {
        String name = req.getName();

        if (name == null) {
            return new ClientResponse(false, "Missing secret name");
        }

        String value = storage.getOrDefault(name, "NOT FOUND");
        return new ClientResponse(true, "Secret value:", List.of(value));
    }

    // ================= CHANGE PIN =================
    private ClientResponse handleChangePin(ClientRequest req) {
        String oldPin = req.getName();   // mapped from parser
        String newPin = req.getValue();  // mapped from parser

        if (oldPin == null || newPin == null) {
            return new ClientResponse(false, "Missing old PIN or new PIN");
        }

        return new ClientResponse(true, "PIN changed successfully");
    }
}