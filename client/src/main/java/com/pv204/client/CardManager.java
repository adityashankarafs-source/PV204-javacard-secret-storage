package com.pv204.client;

import java.util.List;

public class CardManager {

    private MockCardBackend backend;

    public CardManager(MockCardBackend backend) {
        this.backend = backend;
    }

    public ClientResponse handle(ClientRequest request) {

        switch (request.getCommand()) {

            case "add":
                backend.addSecret(request.getName(), request.getValue());
                return new ClientResponse(true, "Secret '" + request.getName() + "' stored successfully.");

            case "list":
                List<String> names = backend.listSecrets();
                return new ClientResponse(true, "Stored secrets:", names);

            case "get":
                String value = backend.getSecret(request.getName());
                if (value == null) {
                    return new ClientResponse(false, "Secret not found.");
                }
                return new ClientResponse(true, value);

            default:
                return new ClientResponse(false, "Unknown command.");
        }
    }
}