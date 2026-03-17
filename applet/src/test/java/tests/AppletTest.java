package tests;

import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.fail;

public class AppletTest {

    @Test
    void appletLoads() {
        try {
            CardSimulator simulator = new CardSimulator();
            AID aid = AIDUtil.create("01FFFF0405060708090102");
            simulator.installApplet(aid, MainApplet.class);
            simulator.selectApplet(aid);
        } catch (Exception e) {
            fail("Applet failed to load: " + e.getMessage());
        }
    }
}