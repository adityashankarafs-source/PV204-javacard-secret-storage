package applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

public class SecretStore implements Constants {

    private byte[] names;
    private byte[] values;
    private byte[] nameLengths;
    private byte[] valueLengths;
    private byte[] used;

    public SecretStore() {

        names = new byte[MAX_SECRETS * MAX_NAME_LEN];
        values = new byte[MAX_SECRETS * MAX_VALUE_LEN];

        nameLengths = new byte[MAX_SECRETS];
        valueLengths = new byte[MAX_SECRETS];

        used = new byte[MAX_SECRETS];
    }

    private short nameOffset(short index) {
        return (short) (index * MAX_NAME_LEN);
    }

    private short valueOffset(short index) {
        return (short) (index * MAX_VALUE_LEN);
    }

    private short find(byte[] buffer, short offset, byte len) {

        short i;

        for (i = 0; i < MAX_SECRETS; i++) {

            if (used[i] == 0) {
                continue;
            }

            if (nameLengths[i] != len) {
                continue;
            }

            if (Util.arrayCompare(
                    names,
                    nameOffset(i),
                    buffer,
                    offset,
                    len) == 0) {
                return i;
            }
        }

        return (short) -1;
    }

    private short freeSlot() {

        short i;

        for (i = 0; i < MAX_SECRETS; i++) {

            if (used[i] == 0) {
                return i;
            }
        }

        return (short) -1;
    }

    public void store(byte[] buffer,
                      short nameOffset,
                      byte nameLen,
                      short valueOffset,
                      byte valueLen) {

        short slot = find(buffer, nameOffset, nameLen);

        if (slot < 0) {
            slot = freeSlot();
        }

        if (slot < 0) {
            ISOException.throwIt(SW_STORAGE_FULL);
        }

        Util.arrayCopy(buffer, nameOffset, names, this.nameOffset(slot), nameLen);
        Util.arrayCopy(buffer, valueOffset, values, this.valueOffset(slot), valueLen);

        nameLengths[slot] = nameLen;
        valueLengths[slot] = valueLen;
        used[slot] = 1;
    }

    public short get(byte[] buffer,
                     short nameOffset,
                     byte nameLen,
                     byte[] out,
                     short outOffset) {

        short slot = find(buffer, nameOffset, nameLen);

        if (slot < 0) {
            ISOException.throwIt(SW_SECRET_NOT_FOUND);
        }

        short src = valueOffset(slot);

        Util.arrayCopy(values, src, out, outOffset, valueLengths[slot]);

        return valueLengths[slot];
    }

    public short list(byte[] out, short offset) {

        short pos = offset;
        short i;

        for (i = 0; i < MAX_SECRETS; i++) {

            if (used[i] == 0) {
                continue;
            }

            out[pos++] = nameLengths[i];

            Util.arrayCopy(
                    names,
                    nameOffset(i),
                    out,
                    pos,
                    nameLengths[i]);

            pos += nameLengths[i];
        }

        return (short) (pos - offset);
    }
}