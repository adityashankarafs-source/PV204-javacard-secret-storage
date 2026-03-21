package com.pv204.client;

public class TransportResponse {
    private final byte[] data;
    private final int sw;

    public TransportResponse(byte[] data, int sw) {
        this.data = data;
        this.sw = sw;
    }

    public byte[] getData() {
        return data;
    }

    public int getSw() {
        return sw;
    }
}
