package com.pv204.client;

public class ClientRequest {

    private String command;
    private String name;
    private String value;
    private String extra;

    public ClientRequest(String command, String name, String value, String extra) {
        this.command = command;
        this.name = name;
        this.value = value;
        this.extra = extra;
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

    public String getExtra() {
        return extra;
    }
}