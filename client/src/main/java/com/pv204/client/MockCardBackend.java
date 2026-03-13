package com.pv204.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MockCardBackend {

    private Map<String, String> storage = new HashMap<>();

    public MockCardBackend() {

        // demo data
        storage.put("gmail", "password123");
        storage.put("bank", "secure456");
    }

    public void addSecret(String name, String value) {
        storage.put(name, value);
    }

    public String getSecret(String name) {
        return storage.get(name);
    }

    public List<String> listSecrets() {
        return new ArrayList<>(storage.keySet());
    }
}