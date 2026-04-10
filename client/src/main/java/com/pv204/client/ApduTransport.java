package com.pv204.client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public interface ApduTransport {
    void connect() throws Exception;
    ResponseAPDU transmit(CommandAPDU command) throws Exception;
}