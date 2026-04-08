package com.pv204.client;

public interface ApduTransport {
    TransportResponse transmit(byte cla, byte ins, byte p1, byte p2, byte[] data);
}
