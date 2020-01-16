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


public final class ECParams {

    protected final short nb_bits;
    protected final byte[] oid;
    protected final byte[] field, a, b, g, r;
    protected final short k;

    protected ECParams(final short nb_bits,
                       final byte[] oid,
                       final byte[] field, /* p */
                       final byte[] a,
                       final byte[] b,
                       final byte[] g,
                       final byte[] r, /* n */
                       final short k) /* h */ {
        this.nb_bits = nb_bits;
        this.oid = oid;
        this.field = field;
        this.a = a;
        this.b = b;
        this.g = g;
        this.r = r;
        this.k = k;
    }


    protected final boolean matchOid(final byte[] buf, final short off, final short len) {
        return (len == (short)oid.length) && (Util.arrayCompare(buf, off, oid, (short)0, len) == 0);
    }

    protected final void setParams(final ECKey key) {
        key.setFieldFP(field, (short)0, (short)field.length);
        key.setA(a, (short)0, (short)a.length);
        key.setB(b, (short)0, (short)b.length);
        key.setG(g, (short)0, (short)g.length);
        key.setR(r, (short)0, (short)r.length);
        key.setK(k);
    }
}
