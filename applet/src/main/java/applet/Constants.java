package applet;

public interface Constants {
    byte APPLET_CLA = (byte) 0xB0;

    byte INS_VERIFY_PIN = 0x10;
    byte INS_CHANGE_PIN = 0x11;

    byte INS_STORE_SECRET = 0x20;
    byte INS_LIST_SECRETS = 0x21;
    byte INS_GET_SECRET = 0x22;

    byte INS_OPEN_SECURE_CHANNEL = 0x30;
    byte INS_SECURE_VERIFY_PIN = 0x31;
    byte INS_SECURE_CHANGE_PIN = 0x32;
    byte INS_SECURE_STORE_SECRET = 0x33;
    byte INS_SECURE_GET_SECRET = 0x34;
    byte INS_SECURE_LIST_SECRETS = 0x35;

    short MAX_SECRETS = 10;
    byte MAX_NAME_LEN = 32;
    byte MAX_VALUE_LEN = 64;
    byte MIN_PIN_LEN = 4;
    byte MAX_PIN_LEN = 8;
    byte PIN_TRY_LIMIT = 5;

    byte NONCE_LEN = 8;
    byte SESSION_KEY_LEN = 16;
    byte MAC_LEN = 16;
    byte MASTER_KEY_LEN = 16;
    byte COUNTER_LEN = 2;
    byte SHA256_LEN = 32;

    byte DIRECTION_REQUEST = 0x55;
    byte DIRECTION_RESPONSE = 0x66;

    short SW_SECRET_NOT_FOUND = (short) 0x6A88;
    short SW_STORAGE_FULL = (short) 0x6A84;
    short SW_DUPLICATE_SECRET = (short) 0x6A89;
    short SW_PIN_REQUIRED = (short) 0x6301;
    short SW_SECURE_CHANNEL_REQUIRED = (short) 0x6302;
    short SW_INVALID_MAC = (short) 0x6303;
    short SW_INVALID_NONCE = (short) 0x6304;
    short SW_INVALID_DATA = (short) 0x6A80;
    short SW_REPLAY_DETECTED = (short) 0x6305;
    short SW_INVALID_HANDSHAKE = (short) 0x6306;
}
