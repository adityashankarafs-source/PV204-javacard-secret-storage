package com.pv204.client;

public class ClientRequest {

    private final String command;
    private final String name;
    private final String value;
    private final String pin;

    public ClientRequest(String command, String name, String value, String pin) {
        this.command = command;
        this.name = name;
        this.value = value;
        this.pin = pin;
    }

    public String getCommand() {
        return command;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getPin() {
        return pin;
    }
}