package com.pv204.client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class CardManager {

    private static final byte CLA = (byte) 0xB0;
    private static final byte INS_VERIFY_PIN = 0x10;
    private static final byte INS_CHANGE_PIN = 0x11;
    private static final byte INS_STORE_SECRET = 0x20;
    private static final byte INS_LIST_SECRETS = 0x21;
    private static final byte INS_GET_SECRET = 0x22;

    private static final int SW_OK = 0x9000;
    private static final int SW_PIN_REQUIRED = 0x6301;
    private static final int SW_SECRET_NOT_FOUND = 0x6A88;

    private final JCardSimTransport transport;
    private boolean connected = false;

    public CardManager() {
        this.transport = new JCardSimTransport();
    }

    public void connect() {
        if (!connected) {
            System.out.println("Connecting to card simulator...");
            transport.connect();
            connected = true;
        }
    }

    public ClientResponse handle(ClientRequest req) {
        connect();

        String command = req.getCommand();

        try {
            switch (command) {
                case "add":
                    return handleAdd(req);
                case "list":
                    return handleList();
                case "get":
                    return handleGet(req);
                case "change-pin":
                    return handleChangePin(req);
                case "help":
                    return helpResponse();
                default:
                    return new ClientResponse(false, "Unknown command");
            }
        } catch (Exception e) {
            return new ClientResponse(false, "Operation failed: " + e.getMessage());
        }
    }

    private ClientResponse helpResponse() {
        List<String> lines = new ArrayList<>();
        lines.add("add <pin> <name> <value>");
        lines.add("list");
        lines.add("get <pin> <name>");
        lines.add("change-pin <oldPin> <newPin>");
        lines.add("help");
        lines.add("exit");
        return new ClientResponse(true, "Usage:", lines);
    }

    private ClientResponse handleAdd(ClientRequest req) throws Exception {
        String pin = req.getPin();
        String name = req.getName();
        String value = req.getValue();

        if (pin == null || name == null || value == null) {
            return new ClientResponse(false, "Usage: add <pin> <name> <value>");
        }

        ResponseAPDU verifyResp = transmit(INS_VERIFY_PIN, pin.getBytes(StandardCharsets.UTF_8));
        if (verifyResp.getSW() != SW_OK) {
            return new ClientResponse(false, "PIN verification failed (SW=" + toHex(verifyResp.getSW()) + ")");
        }

        byte[] payload = encodeNameValue(name, value);
        ResponseAPDU storeResp = transmit(INS_STORE_SECRET, payload);
        if (storeResp.getSW() != SW_OK) {
            return new ClientResponse(false, "Store failed (SW=" + toHex(storeResp.getSW()) + ")");
        }

        return new ClientResponse(true, "Secret stored successfully");
    }

    private ClientResponse handleList() throws Exception {
        ResponseAPDU listResp = transmit(INS_LIST_SECRETS, new byte[0]);

        if (listResp.getSW() != SW_OK) {
            if (listResp.getSW() == SW_PIN_REQUIRED) {
                return new ClientResponse(false, "Listing requires PIN on current applet policy");
            }
            return new ClientResponse(false, "List failed (SW=" + toHex(listResp.getSW()) + ")");
        }

        List<String> names = decodeNameList(listResp.getData());
        return new ClientResponse(true, "Stored secrets:", names);
    }

    private ClientResponse handleGet(ClientRequest req) throws Exception {
        String pin = req.getPin();
        String name = req.getName();

        if (pin == null || name == null) {
            return new ClientResponse(false, "Usage: get <pin> <name>");
        }

        ResponseAPDU verifyResp = transmit(INS_VERIFY_PIN, pin.getBytes(StandardCharsets.UTF_8));
        if (verifyResp.getSW() != SW_OK) {
            return new ClientResponse(false, "PIN verification failed (SW=" + toHex(verifyResp.getSW()) + ")");
        }

        ResponseAPDU getResp = transmit(INS_GET_SECRET, encodeName(name));

        if (getResp.getSW() == SW_SECRET_NOT_FOUND) {
            return new ClientResponse(true, "Secret value:", List.of("NOT FOUND"));
        }

        if (getResp.getSW() != SW_OK) {
            return new ClientResponse(false, "Get failed (SW=" + toHex(getResp.getSW()) + ")");
        }

        String secret = new String(getResp.getData(), StandardCharsets.UTF_8);
        return new ClientResponse(true, "Secret value:", List.of(secret));
    }

    private ClientResponse handleChangePin(ClientRequest req) throws Exception {
        String oldPin = req.getName();
        String newPin = req.getValue();

        if (oldPin == null || newPin == null) {
            return new ClientResponse(false, "Usage: change-pin <oldPin> <newPin>");
        }

        byte[] payload = encodeChangePin(oldPin, newPin);
        ResponseAPDU changeResp = transmit(INS_CHANGE_PIN, payload);

        if (changeResp.getSW() != SW_OK) {
            return new ClientResponse(false, "PIN change failed (SW=" + toHex(changeResp.getSW()) + ")");
        }

        return new ClientResponse(true, "PIN changed successfully");
    }

    private ResponseAPDU transmit(byte ins, byte[] data) throws Exception {
        CommandAPDU cmd = new CommandAPDU(CLA, ins, 0x00, 0x00, data);
        return transport.transmit(cmd);
    }

    private byte[] encodeName(String name) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[1 + nameBytes.length];
        out[0] = (byte) nameBytes.length;
        System.arraycopy(nameBytes, 0, out, 1, nameBytes.length);
        return out;
    }

    private byte[] encodeNameValue(String name, String value) {
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);

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
        byte[] oldBytes = oldPin.getBytes(StandardCharsets.UTF_8);
        byte[] newBytes = newPin.getBytes(StandardCharsets.UTF_8);

        byte[] out = new byte[1 + oldBytes.length + 1 + newBytes.length];
        int pos = 0;

        out[pos++] = (byte) oldBytes.length;
        System.arraycopy(oldBytes, 0, out, pos, oldBytes.length);
        pos += oldBytes.length;

        out[pos++] = (byte) newBytes.length;
        System.arraycopy(newBytes, 0, out, pos, newBytes.length);

        return out;
    }

    private List<String> decodeNameList(byte[] data) {
        List<String> names = new ArrayList<>();
        int pos = 0;

        while (pos < data.length) {
            int len = data[pos] & 0xFF;
            pos++;

            if (pos + len > data.length) {
                break;
            }

            names.add(new String(data, pos, len, StandardCharsets.UTF_8));
            pos += len;
        }

        return names;
    }

    private String toHex(int sw) {
        return String.format("0x%04X", sw & 0xFFFF);
    }
}