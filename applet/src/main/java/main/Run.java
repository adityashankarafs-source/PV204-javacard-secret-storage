package main;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.AID;

public class Run {

    private static final byte CLA = (byte) 0xB0;

    private static final byte INS_VERIFY_PIN   = 0x10;
    private static final byte INS_CHANGE_PIN   = 0x11;
    private static final byte INS_STORE_SECRET = 0x20;
    private static final byte INS_LIST_SECRETS = 0x21;
    private static final byte INS_GET_SECRET   = 0x22;

    public static void main(String[] args) {
        CardSimulator simulator = new CardSimulator();

        AID aid = AIDUtil.create("01FFFF0405060708090102");
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);

        System.out.println("=== JavaCard Secret Storage Demo ===");

        sendAndPrint(simulator, "GET before PIN",
                apdu(INS_GET_SECRET, encodeName("gmail")));

        sendAndPrint(simulator, "VERIFY PIN 1234",
                apdu(INS_VERIFY_PIN, "1234".getBytes()));

        sendAndPrint(simulator, "STORE gmail=pass123",
                apdu(INS_STORE_SECRET, encodeNameValue("gmail", "pass123")));

        sendAndPrint(simulator, "LIST secrets",
                apdu(INS_LIST_SECRETS, new byte[0]));

        sendAndPrint(simulator, "GET gmail",
                apdu(INS_GET_SECRET, encodeName("gmail")));

        sendAndPrint(simulator, "CHANGE PIN 1234 -> 5678",
                apdu(INS_CHANGE_PIN, encodeChangePin("1234", "5678")));

        sendAndPrint(simulator, "VERIFY PIN 5678",
                apdu(INS_VERIFY_PIN, "5678".getBytes()));

        sendAndPrint(simulator, "GET gmail again",
                apdu(INS_GET_SECRET, encodeName("gmail")));
    }

    private static CommandAPDU apdu(byte ins, byte[] data) {
        return new CommandAPDU(CLA, ins, 0x00, 0x00, data);
    }

    private static byte[] encodeName(String name) {
        byte[] nameBytes = name.getBytes();
        byte[] out = new byte[1 + nameBytes.length];
        out[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, 1, nameBytes.length);
        return out;
    }

    private static byte[] encodeNameValue(String name, String value) {
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

    private static byte[] encodeChangePin(String oldPin, String newPin) {
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

    private static void sendAndPrint(CardSimulator simulator, String label, CommandAPDU cmd) {
        ResponseAPDU response = simulator.transmitCommand(cmd);
        byte[] data = response.getData();

        System.out.println("\n[" + label + "]");
        System.out.printf("SW: %04X%n", response.getSW());

        if (data.length > 0) {
            System.out.println("Data (hex): " + toHex(data));

            if (label.startsWith("LIST")) {
                printList(data);
            } else {
                System.out.println("Data (ascii): " + new String(data));
            }
        }
    }

    private static void printList(byte[] data) {
        int pos = 0;
        System.out.println("Secret names:");
        while (pos < data.length) {
            int len = data[pos++] & 0xFF;
            String name = new String(data, pos, len);
            pos += len;
            System.out.println("- " + name);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}