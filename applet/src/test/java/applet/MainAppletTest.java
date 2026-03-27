package applet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MainAppletTest {

    private static final byte CLA = (byte) 0xB0;

    private static final byte INS_VERIFY_PIN          = 0x10;
    private static final byte INS_CHANGE_PIN          = 0x11;
    private static final byte INS_STORE_SECRET        = 0x20;
    private static final byte INS_LIST_SECRETS        = 0x21;
    private static final byte INS_GET_SECRET          = 0x22;
    private static final byte INS_OPEN_SECURE_CHANNEL = 0x30;
    private static final byte INS_INIT_MASTER_KEY     = 0x35;

    private static final short SW_PIN_REQUIRED = (short) 0x6301;
    private static final short SW_WRONG_LENGTH = (short) 0x6700;
    private static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;

    private static final int NONCE_LEN = 8;

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
        assertEquals(SW_PIN_REQUIRED, (short) response.getSW());
    }

    @Test
    void listSecretsWithoutPinFails() {
        ResponseAPDU response = transmit(apdu(INS_LIST_SECRETS, new byte[0]));
        assertEquals(SW_PIN_REQUIRED, (short) response.getSW());
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
    void openSecureChannelWithoutKeyFails() {
        ResponseAPDU response = transmit(apdu(INS_OPEN_SECURE_CHANNEL, sampleNonce()));
        assertEquals(SW_CONDITIONS_NOT_SATISFIED, (short) response.getSW());
    }

    @Test
    void initMasterKeySucceeds() {
        ResponseAPDU response = transmit(apdu(INS_INIT_MASTER_KEY, sampleMasterKey()));
        assertEquals(0x9000, response.getSW());
    }

    @Test
    void initMasterKeyWithWrongLengthFails() {
        byte[] wrongKey = new byte[] { 1, 2, 3, 4, 5 };
        ResponseAPDU response = transmit(apdu(INS_INIT_MASTER_KEY, wrongKey));
        assertEquals(SW_WRONG_LENGTH, (short) response.getSW());
    }

    @Test
    void openSecureChannelAfterInitWorks() {
        assertEquals(0x9000, transmit(apdu(INS_INIT_MASTER_KEY, sampleMasterKey())).getSW());

        ResponseAPDU response = transmit(apdu(INS_OPEN_SECURE_CHANNEL, sampleNonce()));

        assertEquals(0x9000, response.getSW());
        assertEquals(NONCE_LEN, response.getData().length);
    }

    private ResponseAPDU transmit(CommandAPDU cmd) {
        return simulator.transmitCommand(cmd);
    }

    private CommandAPDU apdu(byte ins, byte[] data) {
        return new CommandAPDU(CLA, ins, 0x00, 0x00, data);
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

    private byte[] sampleMasterKey() {
        return new byte[] {
                0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C,
                0x0D, 0x0E, 0x0F, 0x10
        };
    }

    private byte[] sampleNonce() {
        return new byte[] {
                0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18
        };
    }
}