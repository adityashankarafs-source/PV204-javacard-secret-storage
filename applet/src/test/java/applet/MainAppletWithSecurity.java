package applet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class MainAppletWithSecurity implements Constants {

    private CardSimulator simulator;
    private byte[] masterKey;
    private byte[] clientNonce;
    private byte[] cardNonce;
    private byte[] sessionKey;
    private short counter;

    @BeforeEach
    void setUp() throws Exception {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create("01FFFF0405060708090102");
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);

        masterKey = new byte[MASTER_KEY_LEN];
        for (int i = 0; i < MASTER_KEY_LEN; i++) {
            masterKey[i] = (byte) (i + 1);
        }

        ResponseAPDU initResp = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_INIT_MASTER_KEY, 0x00, 0x00, masterKey)
        );
        assertEquals(0x9000, initResp.getSW());

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
        assertEquals("pass123", new String(plain));
    }

    @Test
    void secureListSecretsWorks() throws Exception {
        openSecureChannel();

        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes())).getSW());
        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_STORE_SECRET, encodeNameValue("gmail", "pass123"))).getSW());

        ResponseAPDU listResp = transmit(secureApdu(INS_SECURE_LIST_SECRETS, new byte[0]));
        assertEquals(0x9000, listResp.getSW());

        byte[] plain = decryptSecureResponse(listResp.getData());
        assertTrue(containsName(plain, "gmail"));
    }

    @Test
    void secureChangePinWorks() throws Exception {
        openSecureChannel();

        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_CHANGE_PIN, encodeChangePin("1234", "5678"))).getSW());
        assertEquals(0x9000, transmit(secureApdu(INS_SECURE_VERIFY_PIN, "5678".getBytes())).getSW());
    }

    @Test
    void secureCommandWithoutOpenChannelFails() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_SECURE_LIST_SECRETS, 0x00, 0x00, new byte[0])
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
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

    @Test
    void tamperedMacFails() throws Exception {
        openSecureChannel();

        CommandAPDU cmd = secureApdu(INS_SECURE_VERIFY_PIN, "1234".getBytes());
        byte[] bytes = cmd.getBytes().clone();
        bytes[bytes.length - 1] ^= 0x01;

        ResponseAPDU response = transmit(new CommandAPDU(bytes));
        assertEquals(SW_INVALID_MAC & 0xFFFF, response.getSW());
    }

    private void openSecureChannel() throws Exception {
        ResponseAPDU response = transmit(
                new CommandAPDU(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, clientNonce)
        );
        assertEquals(0x9000, response.getSW());

        byte[] data = response.getData();
        assertEquals(NONCE_LEN + MAC_LEN, data.length);

        cardNonce = Arrays.copyOfRange(data, 0, NONCE_LEN);
        byte[] proof = Arrays.copyOfRange(data, NONCE_LEN, NONCE_LEN + MAC_LEN);

        sessionKey = deriveSessionKey(clientNonce, cardNonce);
        byte[] expectedProof = computeHandshakeProof(clientNonce, cardNonce);

        assertArrayEquals(expectedProof, proof);
        counter = 1;
    }

    private ResponseAPDU transmit(CommandAPDU command) {
        return simulator.transmitCommand(command);
    }

    private CommandAPDU secureApdu(byte ins, byte[] plainPayload) throws Exception {
        byte[] encrypted = plainPayload.clone();
        cryptInPlace(encrypted, counter, (short) 0, DIRECTION_REQUEST);

        byte[] body = new byte[COUNTER_LEN + encrypted.length];
        putShort(body, 0, counter);
        System.arraycopy(encrypted, 0, body, COUNTER_LEN, encrypted.length);

        byte[] mac = computeMac(body, DIRECTION_REQUEST, ins);

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

        byte[] expectedMac = computeMac(body, DIRECTION_RESPONSE, (byte) 0x00);
        assertArrayEquals(expectedMac, mac);

        byte[] cipher = Arrays.copyOfRange(responseData, COUNTER_LEN, COUNTER_LEN + cipherLen);
        cryptInPlace(cipher, respCounter, (short) 0, DIRECTION_RESPONSE);
        return cipher;
    }

    private byte[] deriveSessionKey(byte[] cNonce, byte[] sNonce) throws Exception {
        byte[] input = new byte[MASTER_KEY_LEN + NONCE_LEN + NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(masterKey, 0, input, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        System.arraycopy(cNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        System.arraycopy(sNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        input[pos] = (byte) 0x11;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, SESSION_KEY_LEN);
    }

    private byte[] computeHandshakeProof(byte[] cNonce, byte[] sNonce) throws Exception {
        byte[] input = new byte[MASTER_KEY_LEN + NONCE_LEN + NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(masterKey, 0, input, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;
        System.arraycopy(cNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        System.arraycopy(sNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;
        input[pos] = (byte) 0x7A;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, MAC_LEN);
    }

    private byte[] computeMac(byte[] data, byte direction, byte ins) throws Exception {
        byte[] lenBytes = new byte[2];
        putShort(lenBytes, 0, (short) data.length);

        byte[] input = new byte[SESSION_KEY_LEN + 1 + 1 + 2 + data.length];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        input[pos++] = direction;
        input[pos++] = ins;
        System.arraycopy(lenBytes, 0, input, pos, 2);
        pos += 2;
        System.arraycopy(data, 0, input, pos, data.length);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);
        return Arrays.copyOf(digest, MAC_LEN);
    }

    private void cryptInPlace(byte[] data, short msgCounter, short initialBlockIndex, byte direction) throws Exception {
        int processed = 0;
        short blockIndex = initialBlockIndex;

        while (processed < data.length) {
            byte[] stream = generateKeystream(msgCounter, blockIndex, direction);
            int chunk = Math.min(stream.length, data.length - processed);

            for (int i = 0; i < chunk; i++) {
                data[processed + i] ^= stream[i];
            }

            processed += chunk;
            blockIndex++;
        }
    }

    private byte[] generateKeystream(short msgCounter, short blockIndex, byte direction) throws Exception {
        byte[] input = new byte[SESSION_KEY_LEN + 2 + 2 + 1 + 1];
        int pos = 0;

        System.arraycopy(sessionKey, 0, input, pos, SESSION_KEY_LEN);
        pos += SESSION_KEY_LEN;
        putShort(input, pos, msgCounter);
        pos += 2;
        putShort(input, pos, blockIndex);
        pos += 2;
        input[pos++] = direction;
        input[pos] = (byte) 0x22;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
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

    private boolean containsName(byte[] data, String expected) {
        int pos = 0;
        while (pos < data.length) {
            int len = data[pos] & 0xFF;
            pos++;
            if (pos + len > data.length) {
                return false;
            }
            String name = new String(data, pos, len);
            if (expected.equals(name)) {
                return true;
            }
            pos += len;
        }
        return false;
    }

    private void putShort(byte[] buffer, int offset, short value) {
        buffer[offset] = (byte) ((value >> 8) & 0xFF);
        buffer[offset + 1] = (byte) (value & 0xFF);
    }

    private short getShort(byte[] buffer, int offset) {
        return (short) (((buffer[offset] & 0xFF) << 8) | (buffer[offset + 1] & 0xFF));
    }
}