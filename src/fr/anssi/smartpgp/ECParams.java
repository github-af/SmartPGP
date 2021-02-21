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


public final class ECParams {

    protected final byte[] oid;
    protected final short nb_bits;
    protected final NamedParameterSpec spec;

    protected ECParams(final byte[] oid,
                       final short nb_bits,
                       final NamedParameterSpec spec) {
        this.oid = oid;
        this.nb_bits = nb_bits;
        this.spec = spec;
    }

    protected final boolean matchOid(final byte[] buf, final short off, final short len) {
        return (len == (short)oid.length) && (Util.arrayCompare(buf, off, oid, (short)0, len) == 0);
    }

    private final XECKey createKey(final boolean is_private, final boolean is_persistent) {
        short sens = KeyBuilder.ATTR_PUBLIC;
        byte mem = JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT;

        if(is_private) {
            sens = KeyBuilder.ATTR_PRIVATE;
        }

        if(is_persistent) {
            mem = JCSystem.MEMORY_TYPE_PERSISTENT;
        }

        return (XECKey)KeyBuilder.buildXECKey(this.spec, (short)(mem | sens), true);
    }

    protected final XECPublicKey createPublicKey(final boolean is_persistent) {
        return (XECPublicKey)createKey(false, is_persistent);
    }

    protected final XECPrivateKey createPrivateKey(final boolean is_persistent) {
        return (XECPrivateKey)createKey(true, is_persistent);
    }
}
