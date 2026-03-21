package com.pv204.client;

import java.util.List;

public class CardManager {
    private final SecureSession secureSession;

    public CardManager() {
        this.secureSession = new SecureSession(new JCardSimTransport());
    }

    public ClientResponse handle(ClientRequest request) {
        try {
            switch (request.getCommand()) {
                case Commands.ADD:
                    secureSession.verifyPin(request.getExtra());
                    secureSession.storeSecret(request.getName(), request.getValue());
                    return new ClientResponse(true, "Secret '" + request.getName() + "' stored securely.");
                case Commands.LIST:
                    List<String> names = secureSession.listSecrets();
                    return new ClientResponse(true, "Stored secrets:", names);
                case Commands.GET:
                    secureSession.verifyPin(request.getExtra());
                    String value = secureSession.getSecret(request.getName());
                    return new ClientResponse(true, value);
                case Commands.CHANGE_PIN:
                    secureSession.changePin(request.getValue(), request.getExtra());
                    return new ClientResponse(true, "PIN changed successfully.");
                default:
                    return new ClientResponse(false, "Unknown command.");
            }
        } catch (Exception e) {
            return new ClientResponse(false, e.getMessage());
        }
    }
}
