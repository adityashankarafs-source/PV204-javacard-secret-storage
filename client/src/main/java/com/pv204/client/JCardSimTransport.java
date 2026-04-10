package com.pv204.client;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class JCardSimTransport implements ApduTransport {
    private static final String APPLET_AID_HEX = "01FFFF0405060708090102";

    private CardSimulator simulator;
    private boolean connected;

    @Override
    public void connect() {
        if (connected) {
            return;
        }

        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_HEX);
        simulator.installApplet(aid, MainApplet.class);
        simulator.selectApplet(aid);
        connected = true;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU command) {
        if (!connected) {
            connect();
        }
        return simulator.transmitCommand(command);
    }
}