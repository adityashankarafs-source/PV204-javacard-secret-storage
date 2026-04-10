package applet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.*;

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
    void plainVerifyPinRequiresSecureChannel() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_VERIFY_PIN, 0x00, 0x00, "1234".getBytes())
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void plainGetSecretRequiresSecureChannel() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_GET_SECRET, 0x00, 0x00, encodeName("gmail"))
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void plainListSecretsRequiresSecureChannel() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_LIST_SECRETS, 0x00, 0x00, new byte[0])
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void plainStoreSecretRequiresSecureChannel() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_STORE_SECRET, 0x00, 0x00, encodeNameValue("gmail", "pass123"))
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void plainChangePinRequiresSecureChannel() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_CHANGE_PIN, 0x00, 0x00, encodeChangePin("1234", "5678"))
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    @Test
    void initMasterKeySucceeds() {
        byte[] key = testMasterKey();
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_INIT_MASTER_KEY, 0x00, 0x00, key)
        );
        assertEquals(0x9000, response.getSW());
    }

    @Test
    void initMasterKeyWithWrongLengthFails() {
        byte[] wrong = new byte[MASTER_KEY_LEN - 1];
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_INIT_MASTER_KEY, 0x00, 0x00, wrong)
        );
        assertEquals(ISO7816.SW_WRONG_LENGTH & 0xFFFF, response.getSW());
    }

    @Test
    void openSecureChannelWithoutKeyFails() {
        byte[] nonce = testClientNonce();
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, nonce)
        );
        assertEquals(ISO7816.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF, response.getSW());
    }

    @Test
    void openSecureChannelAfterInitWorks() {
        initKey();

        byte[] nonce = testClientNonce();
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, nonce)
        );

        assertEquals(0x9000, response.getSW());
        assertEquals(NONCE_LEN + MAC_LEN, response.getData().length);
    }

    @Test
    void openSecureChannelWithWrongNonceLengthFails() {
        initKey();

        byte[] wrongNonce = new byte[NONCE_LEN - 1];
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_OPEN_SECURE_CHANNEL, 0x00, 0x00, wrongNonce)
        );

        assertEquals(SW_INVALID_NONCE & 0xFFFF, response.getSW());
    }

    @Test
    void secureCommandWithoutOpenChannelFails() {
        byte[] key = testMasterKey();
        ResponseAPDU init = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_INIT_MASTER_KEY, 0x00, 0x00, key)
        );
        assertEquals(0x9000, init.getSW());

        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_SECURE_LIST_SECRETS, 0x00, 0x00, new byte[0])
        );
        assertEquals(SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, response.getSW());
    }

    private void initKey() {
        ResponseAPDU response = simulator.transmitCommand(
                new CommandAPDU(APPLET_CLA, INS_INIT_MASTER_KEY, 0x00, 0x00, testMasterKey())
        );
        assertEquals(0x9000, response.getSW());
    }

    private byte[] testMasterKey() {
        byte[] key = new byte[MASTER_KEY_LEN];
        for (int i = 0; i < MASTER_KEY_LEN; i++) {
            key[i] = (byte) (i + 1);
        }
        return key;
    }

    private byte[] testClientNonce() {
        byte[] nonce = new byte[NONCE_LEN];
        for (int i = 0; i < NONCE_LEN; i++) {
            nonce[i] = (byte) (0x41 + i);
        }
        return nonce;
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
}