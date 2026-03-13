package com.pv204.client;

public class SecretRecord {

    private String name;
    private String value;

    public SecretRecord(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }
}