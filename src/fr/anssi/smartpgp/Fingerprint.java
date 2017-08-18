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
import javacard.security.*;
import javacardx.apdu.*;
import javacardx.crypto.*;

public final class Fingerprint {
    protected final byte[] data;

    protected Fingerprint() {
        data = new byte[Constants.FINGERPRINT_SIZE];
    }

    protected final void reset(final boolean isRegistering) {
        Common.beginTransaction(isRegistering);
        Util.arrayFillNonAtomic(data, (short)0, Constants.FINGERPRINT_SIZE, (byte)0);
        Common.commitTransaction(isRegistering);
    }

    protected final void set(final byte[] buf, final short off, final short len) {
        if(len != Constants.FINGERPRINT_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }
        Util.arrayCopy(buf, off, data, (short)0, len);
    }

    protected final short write(final byte[] buf, final short off) {
        return Util.arrayCopyNonAtomic(data, (short)0, buf, off, Constants.FINGERPRINT_SIZE);
    }
}
