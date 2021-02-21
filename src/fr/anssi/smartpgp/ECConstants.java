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

public final class ECConstants {

    protected static final byte[] ansix9p256r1_oid =
    {
        (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE,
        (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07
    };

    protected static final byte[] ansix9p384r1_oid =
    {
        (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00,
        (byte)0x22
    };

    protected static final byte[] ansix9p521r1_oid =
    {
        (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00,
        (byte)0x23
    };

    protected static final byte[] brainpoolP256r1_oid =
    {
        (byte)0x2B, (byte)0x24, (byte)0x03, (byte)0x03,
        (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01,
        (byte)0x07
    };

    protected static final byte[] brainpoolP384r1_oid =
    {
        (byte)0x2B, (byte)0x24, (byte)0x03, (byte)0x03,
        (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01,
        (byte)0x0B
    };

    protected static final byte[] brainpoolP512r1_oid =
    {
        (byte)0x2B, (byte)0x24, (byte)0x03, (byte)0x03,
        (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01,
        (byte)0x0D
    };

    protected static final byte[] ed25519_oid =
    {
        (byte)0x09, (byte)0x2B, (byte)0x06, (byte)0x01,
        (byte)0x04, (byte)0x01, (byte)0xDA, (byte)0x47,
        (byte)0x0F, (byte)0x01
    };

    protected static final byte[] x25519_oid =
    {
        (byte)0x0A, (byte)0x2B, (byte)0x06, (byte)0x01,
        (byte)0x04, (byte)0x01, (byte)0x97, (byte)0x55,
        (byte)0x01, (byte)0x05, (byte)0x01
    };
}
