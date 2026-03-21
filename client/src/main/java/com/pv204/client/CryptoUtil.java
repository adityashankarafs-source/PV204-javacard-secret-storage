package com.pv204.client;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class CryptoUtil implements ProtocolConstants {
    private static final byte[] MASTER_KEY = new byte[] {
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, (byte) 0x88,
        0x21, 0x32, 0x43, 0x54,
        0x65, 0x76, 0x07, 0x18
    };

    private CryptoUtil() {
    }

    public static byte[] deriveSessionKey(byte[] clientNonce, byte[] cardNonce) {
        return Arrays.copyOf(sha256(concat(MASTER_KEY, clientNonce, cardNonce)), SESSION_KEY_LEN);
    }

    public static byte[] computeHandshakeProof(byte[] clientNonce, byte[] cardNonce) {
        return Arrays.copyOf(sha256(concat(MASTER_KEY, clientNonce, cardNonce, new byte[] {(byte) 0x7A})), MAC_LEN);
    }

    public static byte[] computeMac(byte[] sessionKey, short counter, byte direction, byte[] body) {
        byte[] counterBytes = shortToBytes(counter);
        return Arrays.copyOf(sha256(concat(sessionKey, new byte[] { direction }, counterBytes, body)), MAC_LEN);
    }

    public static byte[] crypt(byte[] sessionKey, short counter, byte direction, byte[] input) {
        byte[] out = Arrays.copyOf(input, input.length);
        int processed = 0;
        short blockIndex = 0;
        while (processed < out.length) {
            byte[] keystream = sha256(concat(sessionKey, shortToBytes(counter), shortToBytes(blockIndex), new byte[] { direction }));
            int chunk = Math.min(keystream.length, out.length - processed);
            for (int i = 0; i < chunk; i++) {
                out[processed + i] ^= keystream[i];
            }
            processed += chunk;
            blockIndex++;
        }
        return out;
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    public static byte[] shortToBytes(short value) {
        return new byte[] { (byte) (value >> 8), (byte) value };
    }

    public static short bytesToShort(byte[] value, int offset) {
        int hi = value[offset] & 0xFF;
        int lo = value[offset + 1] & 0xFF;
        return (short) ((hi << 8) | lo);
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
