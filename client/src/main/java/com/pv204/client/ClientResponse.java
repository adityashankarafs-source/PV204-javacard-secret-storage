package com.pv204.client;

import java.util.List;

public class ClientResponse {

    private boolean success;
    private String message;
    private List<String> data;

    public ClientResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public ClientResponse(boolean success, String message, List<String> data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public List<String> getData() {
        return data;
    }
}