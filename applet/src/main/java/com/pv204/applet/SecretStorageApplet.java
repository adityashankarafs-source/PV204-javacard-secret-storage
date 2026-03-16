package com.pv204.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class SecretStorageApplet extends Applet {

    private static final byte INS_STORE_SECRET = 0x10;
    private static final byte INS_LIST_SECRETS = 0x20;
    private static final byte INS_GET_SECRET = 0x30;
    private static final byte INS_CHANGE_PIN = 0x40;

    private static final short SW_SECRET_NOT_FOUND = (short) 0x6A88;
    private static final short SW_STORAGE_FULL = (short) 0x6A84;
    private static final short SW_INVALID_PIN = (short) 0x6300;
    private static final short SW_INVALID_DATA = (short) 0x6A80;

    private SecretManager secretManager;
    private PinManager pinManager;

    protected SecretStorageApplet() {
        secretManager = new SecretManager();
        pinManager = new PinManager();
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SecretStorageApplet();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];

        switch (ins) {
            case INS_STORE_SECRET:
                handleStoreSecret(apdu);
                break;
            case INS_LIST_SECRETS:
                handleListSecrets(apdu);
                break;
            case INS_GET_SECRET:
                handleGetSecret(apdu);
                break;
            case INS_CHANGE_PIN:
                handleChangePin(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void handleStoreSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;

        byte nameLen = buffer[offset];
        short nameOffset = (short) (offset + 1);

        short valueLenPos = (short) (nameOffset + nameLen);
        byte valueLen = buffer[valueLenPos];
        short valueOffset = (short) (valueLenPos + 1);

        boolean stored = secretManager.storeSecret(
                buffer, nameOffset, nameLen,
                buffer, valueOffset, valueLen
        );

        if (!stored) {
            ISOException.throwIt(SW_STORAGE_FULL);
        }
    }

    private void handleListSecrets(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short outOffset = 0;

        for (byte i = 0; i < secretManager.getSecretCount(); i++) {
            short len = secretManager.copySecretName(i, buffer, outOffset);
            outOffset += len;

            if (i < (byte) (secretManager.getSecretCount() - 1)) {
                buffer[outOffset] = (byte) '\n';
                outOffset++;
            }
        }

        apdu.setOutgoingAndSend((short) 0, outOffset);
    }

    private void handleGetSecret(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;

        byte pinLen = buffer[offset];
        short pinOffset = (short) (offset + 1);

        if (!pinManager.verify(buffer, pinOffset, pinLen)) {
            ISOException.throwIt(SW_INVALID_PIN);
        }

        short nameLenPos = (short) (pinOffset + pinLen);
        byte nameLen = buffer[nameLenPos];
        short nameOffset = (short) (nameLenPos + 1);

        short index = secretManager.findSecretByName(buffer, nameOffset, nameLen);
        if (index < 0) {
            ISOException.throwIt(SW_SECRET_NOT_FOUND);
        }

        short secretLen = secretManager.copySecretValue((byte) index, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, secretLen);
    }

    private void handleChangePin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;

        byte oldPinLen = buffer[offset];
        short oldPinOffset = (short) (offset + 1);

        if (!pinManager.verify(buffer, oldPinOffset, oldPinLen)) {
            ISOException.throwIt(SW_INVALID_PIN);
        }

        short newPinLenPos = (short) (oldPinOffset + oldPinLen);
        byte newPinLen = buffer[newPinLenPos];
        short newPinOffset = (short) (newPinLenPos + 1);

        pinManager.updatePin(buffer, newPinOffset, newPinLen);
    }
}