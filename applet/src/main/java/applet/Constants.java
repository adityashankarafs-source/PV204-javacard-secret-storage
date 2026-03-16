package applet;

public interface Constants {
    byte APPLET_CLA = (byte) 0xB0;

    byte INS_VERIFY_PIN  = 0x10;
    byte INS_CHANGE_PIN  = 0x11;
    byte INS_STORE_SECRET = 0x20;
    byte INS_LIST_SECRETS = 0x21;
    byte INS_GET_SECRET   = 0x22;

    short MAX_SECRETS = 10;
    byte MAX_NAME_LEN = 32;
    byte MAX_VALUE_LEN = 64;

    byte MIN_PIN_LEN = 4;
    byte MAX_PIN_LEN = 8;
    byte PIN_TRY_LIMIT = 5;

    short SW_SECRET_NOT_FOUND = (short) 0x6A88;
    short SW_STORAGE_FULL = (short) 0x6A84;
    short SW_DUPLICATE_SECRET = (short) 0x6A89;
    short SW_PIN_REQUIRED = (short) 0x6301;
    short SW_INVALID_DATA = (short) 0x6A80;
}