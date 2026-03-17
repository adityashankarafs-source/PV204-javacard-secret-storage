package main;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class Run {

    private static final byte CLA = (byte) 0xB0;

    private static final byte INS_VERIFY_PIN   = 0x10;
    private static final byte INS_CHANGE_PIN   = 0x11;
    private static final byte INS_STORE_SECRET = 0x20;
    private static final byte INS_LIST_SECRETS = 0x21;
    private static final byte INS_GET_SECRET   = 0x22;

    private static final CardSimulator simulator = new CardSimulator();

    public static void main(String[] args) {
        installAndSelectApplet();

        if (args.length == 0) {
            printUsage();
            return;
        }

        int i = 0;

        while (i < args.length) {
            String command = args[i];

            if ("demo".equals(command)) {
                runDemo();
                i++;
                continue;
            }

            if ("verify".equals(command)) {
                if (i + 1 >= args.length) {
                    System.out.println("Usage: verify <pin>");
                    return;
                }
                handleVerify(args[i + 1]);
                i += 2;
                continue;
            }

            if ("store".equals(command)) {
                if (i + 2 >= args.length) {
                    System.out.println("Usage: store <name> <value>");
                    return;
                }
                handleStore(args[i + 1], args[i + 2]);
                i += 3;
                continue;
            }

            if ("list".equals(command)) {
                handleList();
                i += 1;
                continue;
            }

            if ("get".equals(command)) {
                if (i + 1 >= args.length) {
                    System.out.println("Usage: get <name>");
                    return;
                }
                handleGet(args[i + 1]);
                i += 2;
                continue;
            }

            if ("change-pin".equals(command)) {
                if (i + 2 >= args.length) {
                    System.out.println("Usage: change-pin <oldPin> <newPin>");
                    return;
                }
                handleChangePin(args[i + 1], args[i + 2]);
                i += 3;
                continue;
            }

            System.out.println("Unknown command: " + command);
            printUsage();
            return;
        }
    }

    private static void installAndSelectApplet() {
        AID aid = AIDUtil.create("01FFFF0405060708090102");
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);
    }

    private static void handleVerify(String pin) {
        ResponseAPDU response = transmit(apdu(INS_VERIFY_PIN, pin.getBytes()));
        printResponse("VERIFY PIN", response);
    }

    private static void handleStore(String name, String value) {
        ResponseAPDU response = transmit(
                apdu(INS_STORE_SECRET, encodeNameValue(name, value))
        );
        printResponse("STORE SECRET", response);
    }

    private static void handleList() {
        ResponseAPDU response = transmit(apdu(INS_LIST_SECRETS, new byte[0]));
        printResponse("LIST SECRETS", response);

        if (response.getSW() == 0x9000 && response.getData().length > 0) {
            printList(response.getData());
        }
    }

    private static void handleGet(String name) {
        ResponseAPDU response = transmit(
                apdu(INS_GET_SECRET, encodeName(name))
        );
        printResponse("GET SECRET", response);

        if (response.getSW() == 0x9000 && response.getData().length > 0) {
            System.out.println("Secret value: " + new String(response.getData()));
        }
    }

    private static void handleChangePin(String oldPin, String newPin) {
        ResponseAPDU response = transmit(
                apdu(INS_CHANGE_PIN, encodeChangePin(oldPin, newPin))
        );
        printResponse("CHANGE PIN", response);
    }

    private static void runDemo() {
        System.out.println("=== JavaCard Secret Storage Demo ===");

        printResponse("GET before PIN",
                transmit(apdu(INS_GET_SECRET, encodeName("gmail"))));

        printResponse("VERIFY PIN 1234",
                transmit(apdu(INS_VERIFY_PIN, "1234".getBytes())));

        printResponse("STORE gmail=pass123",
                transmit(apdu(INS_STORE_SECRET, encodeNameValue("gmail", "pass123"))));

        ResponseAPDU listResp = transmit(apdu(INS_LIST_SECRETS, new byte[0]));
        printResponse("LIST secrets", listResp);
        if (listResp.getSW() == 0x9000 && listResp.getData().length > 0) {
            printList(listResp.getData());
        }

        ResponseAPDU getResp = transmit(apdu(INS_GET_SECRET, encodeName("gmail")));
        printResponse("GET gmail", getResp);
        if (getResp.getSW() == 0x9000 && getResp.getData().length > 0) {
            System.out.println("Secret value: " + new String(getResp.getData()));
        }

        printResponse("CHANGE PIN 1234 -> 5678",
                transmit(apdu(INS_CHANGE_PIN, encodeChangePin("1234", "5678"))));

        printResponse("VERIFY PIN 5678",
                transmit(apdu(INS_VERIFY_PIN, "5678".getBytes())));
    }

    private static ResponseAPDU transmit(CommandAPDU cmd) {
        return simulator.transmitCommand(cmd);
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

    private static void printResponse(String label, ResponseAPDU response) {
        System.out.println();
        System.out.println("[" + label + "]");
        System.out.printf("SW: %04X%n", response.getSW());

        if (response.getData().length > 0) {
            System.out.println("Data (hex): " + toHex(response.getData()));
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

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  gradlew run --args=\"demo\"");
        System.out.println("  gradlew run --args=\"verify 1234\"");
        System.out.println("  gradlew run --args=\"verify 1234 store gmail pass123 list get gmail\"");
        System.out.println("  gradlew run --args=\"verify 1234 change-pin 1234 5678 verify 5678\"");
    }
}