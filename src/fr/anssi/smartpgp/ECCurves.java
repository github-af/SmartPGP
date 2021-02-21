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

import javacard.security.*;

public final class ECCurves {

    protected final ECParams[] curves;

    protected ECCurves() {
        final ECParams ansix9p256r1 =
            new ECParams(ECConstants.ansix9p256r1_oid,
                         (short)256,
                         NamedParameterSpec.getInstance(NamedParameterSpec.SECP256R1));

        final ECParams ansix9p384r1 =
            new ECParams(ECConstants.ansix9p384r1_oid,
                         (short)384,
                         NamedParameterSpec.getInstance(NamedParameterSpec.SECP384R1));

        final ECParams ansix9p521r1 =
            new ECParams(ECConstants.ansix9p521r1_oid,
                         (short)521,
                         NamedParameterSpec.getInstance(NamedParameterSpec.SECP521R1));

        final ECParams brainpoolP256r1 =
            new ECParams(ECConstants.brainpoolP256r1_oid,
                         (short)256,
                         NamedParameterSpec.getInstance(NamedParameterSpec.BRAINPOOLP256R1));

        final ECParams brainpoolP384r1 =
            new ECParams(ECConstants.brainpoolP384r1_oid,
                         (short)384,
                         NamedParameterSpec.getInstance(NamedParameterSpec.BRAINPOOLP384R1));

        final ECParams brainpoolP512r1 =
            new ECParams(ECConstants.brainpoolP512r1_oid,
                         (short)512,
                         NamedParameterSpec.getInstance(NamedParameterSpec.BRAINPOOLP512R1));

        final ECParams ed25519 =
            new ECParams(ECConstants.ed25519_oid,
                         (short)255,
                         NamedParameterSpec.getInstance(NamedParameterSpec.ED25519));

        final ECParams x25519 =
            new ECParams(ECConstants.x25519_oid,
                         (short)255,
                         NamedParameterSpec.getInstance(NamedParameterSpec.X25519));

        curves = new ECParams[]{
            ansix9p256r1,
            ansix9p384r1,
            ansix9p521r1,
            brainpoolP256r1,
            brainpoolP384r1,
            brainpoolP512r1,
            ed25519,
            x25519
        };
    }

    protected final ECParams findByOid(final byte[] buf,
                                       final short off,
                                       final byte len) {
        byte i = 0;
        while(i < curves.length) {
            if(curves[i].matchOid(buf, off, len)) {
                return curves[i];
            }
            ++i;
        }

        return null;
    }
}
