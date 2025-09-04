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
import javacardx.crypto.*;

public final class Common {
    protected final Cipher cipher_aes_cbc_nopad;
    protected final Cipher cipher_rsa_pkcs1;

    protected final Signature sign_ecdsa_sha;
    protected final Signature sign_ecdsa_sha_224;
    protected final Signature sign_ecdsa_sha_256;
    protected final Signature sign_ecdsa_sha_384;
    protected final Signature sign_ecdsa_sha_512;
    protected final Signature sign_eddsaph;

    protected final KeyAgreement ka_ec_dh;

    protected final RandomData random;

    protected Common() {
        cipher_aes_cbc_nopad = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        sign_ecdsa_sha = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        sign_ecdsa_sha_224 = Signature.getInstance(Signature.ALG_ECDSA_SHA_224, false);
        sign_ecdsa_sha_256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sign_ecdsa_sha_384 = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
        sign_ecdsa_sha_512 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
        sign_eddsaph = Signature.getInstance(Signature.SIG_CIPHER_EDDSAPH, false);

        ka_ec_dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        random = RandomData.getInstance(RandomData.ALG_TRNG);
    }

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

    protected static final short aesKeyLength(final ECParams params) {
        if(params.nb_bits < (short)512) {
            return (short)16;
        } else {
            return (short)32;
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

    protected static final short writeAlgorithmInformation(final ECCurves ec,
                                                           final byte key_tag, final boolean is_dec,
                                                           final byte[] buf, short off) {
        for(short i = 0; i < ec.curves.length; ++i) {
            buf[off++] = key_tag;
            buf[off++] = (byte)(1 + ec.curves[i].oid.length + 1); /* len */
            if(is_dec) buf[off++] = (byte)0x12; /* ECDH */
            else buf[off++] = (byte)0x13; /* ECDSA */
            off = Util.arrayCopyNonAtomic(ec.curves[i].oid, (short)0,
                                          buf, off,
                                          (short)ec.curves[i].oid.length);
            buf[off++] = (byte)0xff; /* with public key */
        }

        for(short m = 2; m <= 4; ++m) {
            for(byte form = Constants.RSA_IMPORT_SUPPORTS_FORMAT_1 ? 1 : 3; form <= 3; form += 2) {
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

    protected static final void requestDeletion() {
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }
}
