package com.pv204.applet;

import javacard.framework.Util;

public class SecretManager {

    private static final byte MAX_SECRETS = 5;
    private static final short MAX_NAME_LEN = 20;
    private static final short MAX_VALUE_LEN = 64;

    private byte[][] names;
    private byte[][] values;
    private short[] nameLengths;
    private short[] valueLengths;
    private byte secretCount;

    public SecretManager() {
        names = new byte[MAX_SECRETS][MAX_NAME_LEN];
        values = new byte[MAX_SECRETS][MAX_VALUE_LEN];
        nameLengths = new short[MAX_SECRETS];
        valueLengths = new short[MAX_SECRETS];
        secretCount = 0;
    }

    public boolean storeSecret(byte[] name, short nameOffset, short nameLen,
                               byte[] value, short valueOffset, short valueLen) {
        if (secretCount >= MAX_SECRETS) {
            return false;
        }

        if (nameLen > MAX_NAME_LEN || valueLen > MAX_VALUE_LEN) {
            return false;
        }

        Util.arrayCopy(name, nameOffset, names[secretCount], (short) 0, nameLen);
        Util.arrayCopy(value, valueOffset, values[secretCount], (short) 0, valueLen);
        nameLengths[secretCount] = nameLen;
        valueLengths[secretCount] = valueLen;
        secretCount++;
        return true;
    }

    public byte getSecretCount() {
        return secretCount;
    }

    public short copySecretName(byte index, byte[] outBuffer, short outOffset) {
        Util.arrayCopy(names[index], (short) 0, outBuffer, outOffset, nameLengths[index]);
        return nameLengths[index];
    }

    public short findSecretByName(byte[] input, short offset, short length) {
        for (byte i = 0; i < secretCount; i++) {
            if (nameLengths[i] == length) {
                if (Util.arrayCompare(names[i], (short) 0, input, offset, length) == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    public short copySecretValue(byte index, byte[] outBuffer, short outOffset) {
        Util.arrayCopy(values[index], (short) 0, outBuffer, outOffset, valueLengths[index]);
        return valueLengths[index];
    }
}