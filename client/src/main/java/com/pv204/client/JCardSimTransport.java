package com.pv204.client;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class JCardSimTransport implements ApduTransport, ProtocolConstants {
    private final CardSimulator simulator;

    public JCardSimTransport() {
        this.simulator = new CardSimulator();
        AID appletAid = AIDUtil.create(APPLET_AID_HEX);
        simulator.installApplet(appletAid, MainApplet.class);
        simulator.selectApplet(appletAid);
    }

    @Override
    public TransportResponse transmit(byte cla, byte ins, byte p1, byte p2, byte[] data) {
        CommandAPDU command = new CommandAPDU(cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF, data);
        ResponseAPDU response = simulator.transmitCommand(command);
        return new TransportResponse(response.getData(), response.getSW());
    }
}
