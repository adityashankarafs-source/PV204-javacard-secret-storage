package applet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class MainAppletWithSecurity implements Constants {

    private static final byte[] MASTER_KEY = new byte[] {
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, (byte) 0x88,
            0x21, 0x32, 0x43, 0x54,
            0x65, 0x76, 0x07, 0x18
    };

    private CardSimulator simulator;
    private byte[] clientNonce;
    private byte[] cardNonce;
    private byte[] sessionKey;
    private short counter;

    @BeforeEach
    void setUp() {
    simulator = new CardSimulator();
    AID aid = AIDUtil.create("01FFFF0405060708090102");
    simulator.installApplet(aid, MainApplet.class);
    simulator.selectApplet(aid);

    clientNonce = new byte[NONCE_LEN];
    for (int i = 0; i < NONCE_LEN; i++) {
        clientNonce[i] = (byte) (0x41 + i);
    }

    counter = 1;
    }

    @Test
    void secureOpenReturnsValidHandshakeProof() throws Exception {
        openSecureChannel();
        assertNotNull(cardNonce);
        assertEquals(NONCE_LEN, cardNonce.length);
        assertNotNull(sessionKey);
        assertEquals(SESSION_KEY_LEN, sessionKey.length);
    }

    @Test
    void secureVerifyPinSucceeds() throws Exception {
        openSecureChannel();
        ResponseAPDU response = transmit(secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes()));
        assertEquals(0x9000, response.getSW());
    }

    @Test
    void secureStoreAndGetSecretWorks() throws Exception {
        openSecureChannel();

        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes())).getSW());

        byte[] storePayload = encodeNameValue("gmail", "pass123");
        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_STORE_SECRET, storePayload)).getSW());

        ResponseAPDU getResp = transmit(secureApdu(INS_SECURE_GET_SECRET, encodeName("gmail")));
        assertEquals(0x9000, getResp.getSW());

        byte[] plain = decryptSecureResponse(getResp.getData());
        assertArrayEquals("pass123".getBytes(), plain);
    }

    @Test
    void secureListSecretsWorks() throws Exception {
        openSecureChannel();

        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes())).getSW());
        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_STORE_SECRET, encodeNameValue("gmail", "pass123"))).getSW());

        ResponseAPDU listResp = transmit(secureApdu(INS_SECURE_LIST_SECRETS, new byte[0]));
        assertEquals(0x9000, listResp.getSW());

        byte[] plain = decryptSecureResponse(listResp.getData());
        assertArrayEquals(new byte[] { 0x05, 'g', 'm', 'a', 'i', 'l' }, plain);
    }

    @Test
    void secureChangePinWorks() throws Exception {
        openSecureChannel();

        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes())).getSW());

        ResponseAPDU changeResp = transmit(secureApdu(INS_SECURE_CHANGE_PIN, encodeChangePin("1234", "5678")));
        assertEquals(0x9000, changeResp.getSW());

        ResponseAPDU verifyNew = transmit(secureApdu(INS_SECURE_VERIFY_PIN, "5678".getBytes()));
        assertEquals(0x9000, verifyNew.getSW());
    }

    @Test
    void secureCommandWithoutOpenChannelFails() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create("01FFFF0405060708090102");
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);

        byte[] dummy = new byte[COUNTER_LEN + MAC_LEN];
        ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(APPLET_CLA, INS_SECURE_VERIFY_PIN, 0x00, 0x00, dummy));
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void tamperedMacFails() throws Exception {
        openSecureChannel();
        CommandAPDU cmd = secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes());
        byte[] bytes = cmd.getBytes().clone();

        bytes[bytes.length - 1] ^= 0x01;

        ResponseAPDU response = transmit(new CommandAPDU(bytes));
        assertEquals(SW_INVALID_MAC & 0xFFFF, response.getSW());
    }

    @Test
    void replayCounterFails() throws Exception {
        openSecureChannel();
        CommandAPDU first = secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes());
        ResponseAPDU ok = transmit(first);
        assertEquals(0x9000, ok.getSW());

        ResponseAPDU replay = transmit(first);
        assertEquals(SW_REPLAY_DETECTED & 0xFFFF, replay.getSW());
    }

    private void openSecureChannel() throws Exception {
    ResponseAPDU response = transmit(new CommandAPDU(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, clientNonce));
    System.out.println("OPEN SW = " + Integer.toHexString(response.getSW()));

    assertEquals(0x9000, response.getSW());

    byte[] data = response.getData();
    System.out.println("OPEN DATA LEN = " + data.length);

    assertEquals(NONCE_LEN + MAC_LEN, data.length);

    cardNonce = Arrays.copyOfRange(data, 0, NONCE_LEN);
    byte[] proof = Arrays.copyOfRange(data, NONCE_LEN, NONCE_LEN + MAC_LEN);

    sessionKey = deriveSessionKey(clientNonce, cardNonce);
    byte[] expectedProof = computeHandshakeProof(clientNonce, cardNonce);

    assertArrayEquals(expectedProof, proof);
    }

    private CommandAPDU secureApdu(byte ins, byte[] plainPayload) throws Exception {
        byte[] encrypted = plainPayload.clone();
        cryptInPlace(encrypted, counter, (short) 0, DIRECTION_REQUEST);

        byte[] body = new byte[COUNTER_LEN + encrypted.length];
        putShort(body, 0, counter);
        System.arraycopy(encrypted, 0, body, COUNTER_LEN, encrypted.length);

        byte[] mac = computeMac(body, DIRECTION_REQUEST);

        byte[] full = new byte[body.length + MAC_LEN];
        System.arraycopy(body, 0, full, 0, body.length);
        System.arraycopy(mac, 0, full, body.length, MAC_LEN);

        counter++;
        return new CommandAPDU(APPLET_CLA, ins, 0x00, 0x00, full);
    }

    private byte[] decryptSecureResponse(byte[] responseData) throws Exception {
        assertTrue(responseData.length >= COUNTER_LEN + MAC_LEN);

        short respCounter = getShort(responseData, 0);
        int cipherLen = responseData.length - COUNTER_LEN - MAC_LEN;

        byte[] body = Arrays.copyOfRange(responseData, 0, COUNTER_LEN + cipherLen);
        byte[] mac = Arrays.copyOfRange(responseData, COUNTER_LEN + cipherLen, responseData.length);

        byte[] expectedMac = computeMac(body, DIRECTION_RESPONSE);
        assertArrayEquals(expectedMac, mac);

        byte[] cipher = Arrays.copyOfRange(responseData, COUNTER_LEN, COUNTER_LEN + cipherLen);
        cryptInPlace(cipher, respCounter, (short) 0, DIRECTION_RESPONSE);
        return cipher;
    }

    private byte[] deriveSessionKey(byte[] clientNonce, byte[] cardNonce) throws Exception {
        byte[] input = new byte[MASTER_KEY_LEN + NONCE_LEN + NONCE_LEN];
        int pos = 0;

        System.arraycopy(MASTER_KEY, 0, input, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        System.arraycopy(clientNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        System.arraycopy(cardNonce, 0, input, pos, NONCE_LEN);

        byte[] digest = sha256(input);
        return Arrays.copyOf(digest, SESSION_KEY_LEN);
    }

    private byte[] computeHandshakeProof(byte[] clientNonce, byte[] cardNonce) throws Exception {
        byte[] input = new byte[MASTER_KEY_LEN + NONCE_LEN + NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(MASTER_KEY, 0, input, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        System.arraycopy(clientNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        System.arraycopy(cardNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        input[pos] = (byte) 0x7A;

        byte[] digest = sha256(input);
        return Arrays.copyOf(digest, MAC_LEN);
    }

    private byte[] computeMac(byte[] data, byte direction) throws Exception {
        byte[] input = new byte[SESSION_KEY_LEN + 1 + data.length];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        input[pos++] = direction;
        System.arraycopy(data, 0, input, pos, data.length);

        byte[] digest = sha256(input);
        return Arrays.copyOf(digest, MAC_LEN);
    }

    private void cryptInPlace(byte[] data, short counter, short initialBlockIndex, byte direction) throws Exception {
        int processed = 0;
        short blockIndex = initialBlockIndex;

        while (processed < data.length) {
            byte[] keystream = generateKeystream(counter, blockIndex, direction);
            int chunk = Math.min(keystream.length, data.length - processed);

            for (int i = 0; i < chunk; i++) {
                data[processed + i] ^= keystream[i];
            }

            processed += chunk;
            blockIndex++;
        }
    }

    private byte[] generateKeystream(short counter, short blockIndex, byte direction) throws Exception {
        byte[] input = new byte[SESSION_KEY_LEN + 2 + 2 + 1];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        putShort(input, pos, counter);
        pos += 2;
        putShort(input, pos, blockIndex);
        pos += 2;
        input[pos] = direction;

        return sha256(input);
    }

    private byte[] sha256(byte[] input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }

    private ResponseAPDU transmit(CommandAPDU cmd) {
        return simulator.transmitCommand(cmd);
    }

    private byte[] encodeName(String name) {
        byte[] nameBytes = name.getBytes();
        byte[] out = new byte[1 + nameBytes.length];
        out[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, 1, nameBytes.length);
        return out;
    }

    private byte[] encodeNameValue(String name, String value) {
        byte[] nameBytes = name.getBytes();
        byte[] valueBytes = value.getBytes();

        byte[] out = new byte[1 + nameBytes.length + 1 + valueBytes.length];
        int pos = 0;

        out[pos++] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, pos, nameBytes.length);
        pos += nameBytes.length;

        out[pos++] = (byte) valueBytes.length;
        System.arraycopy(valueBytes, 0, out, pos, valueBytes.length);

        return out;
    }

    private byte[] encodeChangePin(String oldPin, String newPin) {
        byte[] oldBytes = oldPin.getBytes();
        byte[] newBytes = newPin.getBytes();

        byte[] out = new byte[1 + oldBytes.length + 1 + newBytes.length];
        int pos = 0;

        out[pos++] = (byte) oldBytes.length;
        System.arraycopy(oldBytes, 0, out, pos, oldBytes.length);
        pos += oldBytes.length;

        out[pos++] = (byte) newBytes.length;
        System.arraycopy(newBytes, 0, out, pos, newBytes.length);

        return out;
    }

    private void putShort(byte[] buffer, int offset, short value) {
        buffer[offset] = (byte) ((value >> 8) & 0xFF);
        buffer[offset + 1] = (byte) (value & 0xFF);
    }

    private short getShort(byte[] buffer, int offset) {
        return (short) (((buffer[offset] & 0xFF) << 8) | (buffer[offset + 1] & 0xFF));
    }
}