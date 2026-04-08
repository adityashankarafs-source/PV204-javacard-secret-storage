package com.pv204.client;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class JCardSimTransport {

    private static final String APPLET_AID_HEX = "01FFFF0405060708090102";

    private CardSimulator simulator;
    private boolean initialized = false;

    public void connect() {
        if (initialized) {
            return;
        }

        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_HEX);
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);

        initialized = true;
    }

    public ResponseAPDU transmit(CommandAPDU command) {
        if (!initialized) {
            throw new IllegalStateException("Transport not connected");
        }
        return simulator.transmitCommand(command);
    }
}