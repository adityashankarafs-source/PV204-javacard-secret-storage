package com.pv204.client;

public interface ProtocolConstants {
    byte APPLET_CLA = (byte) 0xB0;

    byte INS_OPEN_SECURE_CHANNEL = 0x30;
    byte INS_SECURE_VERIFY_PIN = 0x31;
    byte INS_SECURE_CHANGE_PIN = 0x32;
    byte INS_SECURE_STORE_SECRET = 0x33;
    byte INS_SECURE_GET_SECRET = 0x34;
    byte INS_SECURE_LIST_SECRETS = 0x35;

    byte NONCE_LEN = 8;
    byte SESSION_KEY_LEN = 16;
    byte MAC_LEN = 16;
    byte MASTER_KEY_LEN = 16;
    byte COUNTER_LEN = 2;
    byte DIRECTION_REQUEST = 0x55;
    byte DIRECTION_RESPONSE = 0x66;

    int SW_OK = 0x9000;
    int SW_INVALID_MAC = 0x6303;
    int SW_REPLAY_DETECTED = 0x6305;

    String APPLET_AID_HEX = "01FFFF0405060708090102";
}
