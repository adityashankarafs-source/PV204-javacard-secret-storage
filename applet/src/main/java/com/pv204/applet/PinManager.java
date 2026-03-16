package com.pv204.applet;

import javacard.framework.OwnerPIN;

public class PinManager {

    private static final byte MAX_TRIES = 3;
    private static final byte PIN_LENGTH = 4;

    private OwnerPIN pin;

    public PinManager() {
        pin = new OwnerPIN(MAX_TRIES, PIN_LENGTH);
        byte[] defaultPin = { '1', '2', '3', '4' };
        pin.update(defaultPin, (short) 0, PIN_LENGTH);
    }

    public boolean verify(byte[] buffer, short offset, byte length) {
        return pin.check(buffer, offset, length);
    }

    public void updatePin(byte[] buffer, short offset, byte length) {
        pin.update(buffer, offset, length);
    }

    public boolean isValidated() {
        return pin.isValidated();
    }

    public void reset() {
        pin.reset();
    }
}