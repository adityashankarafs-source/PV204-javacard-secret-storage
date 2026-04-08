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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MainAppletTest implements Constants {

    private CardSimulator simulator;

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create("01FFFF0405060708090102");
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);
    }

    @Test
    void getSecretWithoutPinFails() {
        ResponseAPDU response = transmit(apdu(INS_GET_SECRET, encodeName("gmail")));
        assertEquals(SW_PIN_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void listSecretsWithoutPinWorks() {
        ResponseAPDU response = transmit(apdu(INS_LIST_SECRETS, new byte[0]));
        assertEquals(0x9000, response.getSW());
        assertEquals(0, response.getData().length);
    }

    @Test
    void verifyPinSucceeds() {
        ResponseAPDU response = transmit(apdu(INS_VERIFY_PIN, "1234".getBytes()));
        assertEquals(0x9000, response.getSW());
    }

    @Test
    void storeAndGetSecretWorksAfterVerify() {
        assertEquals(0x9000, transmit(apdu(INS_VERIFY_PIN, "1234".getBytes())).getSW());
        assertEquals(0x9000, transmit(apdu(INS_STORE_SECRET, encodeNameValue("gmail", "pass123"))).getSW());

        ResponseAPDU response = transmit(apdu(INS_GET_SECRET, encodeName("gmail")));

        assertEquals(0x9000, response.getSW());
        assertArrayEquals("pass123".getBytes(), response.getData());
    }

    @Test
    void listSecretsReturnsStoredName() {
        assertEquals(0x9000, transmit(apdu(INS_VERIFY_PIN, "1234".getBytes())).getSW());
        assertEquals(0x9000, transmit(apdu(INS_STORE_SECRET, encodeNameValue("gmail", "pass123"))).getSW());

        ResponseAPDU response = transmit(apdu(INS_LIST_SECRETS, new byte[0]));

        assertEquals(0x9000, response.getSW());
        assertArrayEquals(new byte[] { 0x05, 'g', 'm', 'a', 'i', 'l' }, response.getData());
    }

    @Test
    void changePinWorks() {
        assertEquals(0x9000, transmit(apdu(INS_VERIFY_PIN, "1234".getBytes())).getSW());

        ResponseAPDU changeResp = transmit(apdu(INS_CHANGE_PIN, encodeChangePin("1234", "5678")));
        assertEquals(0x9000, changeResp.getSW());

        ResponseAPDU verifyNew = transmit(apdu(INS_VERIFY_PIN, "5678".getBytes()));
        assertEquals(0x9000, verifyNew.getSW());
    }

    @Test
    void changePinWithWrongOldPinFails() {
        ResponseAPDU response = transmit(apdu(INS_CHANGE_PIN, encodeChangePin("9999", "5678")));
        assertEquals(0x6982, response.getSW());
    }

    @Test
    void openSecureChannelWorksWithoutProvisioningStep() throws Exception {
        byte[] clientNonce = sampleNonce();

        ResponseAPDU response = transmit(apdu(INS_OPEN_SECURE_CHANNEL, clientNonce));

        assertEquals(0x9000, response.getSW());

        byte[] data = response.getData();
        assertEquals(NONCE_LEN + MAC_LEN, data.length);

        byte[] cardNonce = Arrays.copyOfRange(data, 0, NONCE_LEN);
        byte[] proof = Arrays.copyOfRange(data, NONCE_LEN, NONCE_LEN + MAC_LEN);

        byte[] expectedProof = computeHandshakeProof(clientNonce, cardNonce);
        assertArrayEquals(expectedProof, proof);
    }

    @Test
    void openSecureChannelWithWrongNonceLengthFails() {
        byte[] wrongNonce = new byte[] { 1, 2, 3, 4, 5 };

        ResponseAPDU response = transmit(apdu(INS_OPEN_SECURE_CHANNEL, wrongNonce));

        assertEquals(SW_INVALID_NONCE & 0xFFFF, response.getSW());
    }

    @Test
    void secureCommandWithoutOpenChannelFails() {
        byte[] dummy = new byte[COUNTER_LEN + MAC_LEN];
        ResponseAPDU response = transmit(new CommandAPDU(APPLET_CLA, INS_SECURE_VERIFY_PIN, 0x00, 0x00, dummy));
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    private ResponseAPDU transmit(CommandAPDU cmd) {
        return simulator.transmitCommand(cmd);
    }

    private CommandAPDU apdu(byte ins, byte[] data) {
        return new CommandAPDU(APPLET_CLA, ins, 0x00, 0x00, data);
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

    private byte[] sampleNonce() {
        return new byte[] {
                0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18
        };
    }

    private byte[] computeHandshakeProof(byte[] clientNonce, byte[] cardNonce) throws Exception {
        byte[] masterKey = new byte[] {
                0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, (byte) 0x88,
                0x21, 0x32, 0x43, 0x54,
                0x65, 0x76, 0x07, 0x18
        };

        byte[] input = new byte[MASTER_KEY_LEN + NONCE_LEN + NONCE_LEN + 1];
        int pos = 0;

        System.arraycopy(masterKey, 0, input, pos, MASTER_KEY_LEN);
        pos += MASTER_KEY_LEN;

        System.arraycopy(clientNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;

        System.arraycopy(cardNonce, 0, input, pos, NONCE_LEN);
        pos += NONCE_LEN;

        input[pos] = (byte) 0x7A;

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input);

        return Arrays.copyOf(digest, MAC_LEN);
    }
}