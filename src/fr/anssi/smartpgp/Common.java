/*
  SmartPGP : JavaCard implementation of OpenPGP card v3 specification
  https://github.com/ANSSI-FR/SmartPGP
  Copyright (C) 2016 ANSSI

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package fr.anssi.smartpgp;

import javacard.framework.*;

public final class Common {

    protected static final void beginTransaction(final boolean isRegistering) {
        if(!isRegistering) {
            JCSystem.beginTransaction();
        }
    }

    protected static final void commitTransaction(final boolean isRegistering) {
        if(!isRegistering) {
            JCSystem.commitTransaction();
        }
    }

    protected static final short writeLength(final byte[] buf, short off, final short len) {
        if(len > 0xff) {
            buf[off] = (byte)0x82;
            return Util.setShort(buf, (short)(off+1), len);
        }

        if(len > 0x7f) {
            buf[off++] = (byte)0x81;
            buf[off++] = (byte)(len & 0xff);
            return off;
        }

        buf[off++] = (byte)(len & 0x7f);
        return off;
    }

    protected static final short skipLength(final byte[] buf, final short off, final short len) {

        if(len < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return off;
        }

        if((buf[off] & (byte)0x80) == 0) {
            return (short)(off + 1);
        }

        switch(buf[off]) {
        case (byte)0x81:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return off;
            }
            return (short)(off + 2);

        case (byte)0x82:
            if(len < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return off;
            }
            return (short)(off + 3);

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return off;
        }
    }

    protected static final short readLength(final byte[] buf, final short off, final short len) {

        if(len < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return (short)0;
        }

        if((buf[off] & (byte)0x80) == 0) {
            return Util.makeShort((byte)0, buf[off]);
        }

        switch(buf[off]) {
        case (byte)0x81:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return (short)0;
            }
            return Util.makeShort((byte)0, buf[(short)(off + 1)]);

        case (byte)0x82:
            if(len < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return (short)0;
            }
            return Util.getShort(buf, (short)(off + 1));

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return (short)0;
        }
    }

    protected static final short bitsToBytes(final short bits) {
        return (short)((bits / 8) + (short)(((bits % 8) == 0) ? 0 : 1));
    }


    protected static final void arrayLeftShift(final byte[] inBuf, short inOff,
                                               final byte[] outBuf, short outOff,
                                               final short len) {
        if(len > 0) {
            outBuf[outOff++] = (byte)(inBuf[inOff++] << 1);
            for(short i = 1; i < len; ++i) {
                if((inBuf[inOff] & (byte)0x80) != (byte)0) {
                    outBuf[(short)(outOff - 1)] |= (byte)0x01;
                }
                outBuf[outOff++] = (byte)(inBuf[inOff++] << 1);
            }
        }
    }

    protected static final void arrayXor(final byte[] inBuf1, short inOff1,
                                         final byte[] inBuf2, short inOff2,
                                         final byte[] outBuf, short outOff,
                                         final short len) {
        for(short i = 0; i < len; ++i) {
            outBuf[outOff++] = (byte)(inBuf1[inOff1++] ^ inBuf2[inOff2++]);
        }
    }

    protected static final short writeAlgorithmInformation(final byte key_tag,
                                                           final byte[] buf, short off) {
        for(short m = 2; m <= 4; ++m) {
            for(byte form = 1; form <= 3; form += 2) {
                buf[off++] = key_tag;
                buf[off++] = (byte)6; /* len */
                buf[off++] = (byte)0x01; /* RSA */
                off = Util.setShort(buf, off, (short)(m * 1024)); /* modulus bit size */
                off = Util.setShort(buf, off, (short)0x11); /* 65537 = 17 bits public exponent size */
                buf[off++] = form;
            }
        }

        return off;
    }
}
