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

public final class PGPKey {

    protected final Fingerprint fingerprint;

    protected final byte[] generation_date;

    protected final byte[] certificate;
    protected short certificate_length;

    protected final byte[] attributes;
    protected byte attributes_length;

    protected final boolean is_secure_messaging_key;

    private KeyPair keys;

    private final Cipher cipher_rsa_pkcs1;

    protected PGPKey(final boolean for_secure_messaging) {

        is_secure_messaging_key = for_secure_messaging;

        if(is_secure_messaging_key) {
            cipher_rsa_pkcs1 = null;
            fingerprint = null;
            generation_date = null;
        } else {
            cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
            fingerprint = new Fingerprint();
            generation_date = new byte[Constants.GENERATION_DATE_SIZE];
        }

        certificate = new byte[Constants.cardholderCertificateMaxLength()];
        certificate_length = 0;

        attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];
        attributes_length = 0;

        reset(true);
    }

    private final void resetKeys(final boolean isRegistering) {
        if(keys != null) {
            keys.getPrivate().clearKey();
            keys.getPublic().clearKey();
            keys = null;
        }

        if(certificate_length > 0) {
            certificate_length = (short)0;
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }

        if(!is_secure_messaging_key) {
            fingerprint.reset(isRegistering);

            Util.arrayFillNonAtomic(generation_date, (short)0, Constants.GENERATION_DATE_SIZE, (byte)0);
        }
    }

    protected final void reset(final boolean isRegistering) {
        resetKeys(isRegistering);

        Common.beginTransaction(isRegistering);
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
            attributes_length = (byte)0;
        }

        if(is_secure_messaging_key) {
            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
        } else {
            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;
        }
        Common.commitTransaction(isRegistering);
    }

    protected final boolean isInitialized() {
        return (keys != null) && keys.getPrivate().isInitialized() && keys.getPublic().isInitialized();
    }

    protected final void setCertificate(final byte[] buf, final short off, final short len) {
        if((len < 0) ||
           (len > Constants.cardholderCertificateMaxLength())) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        JCSystem.beginTransaction();
        if(certificate_length > 0) {
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, certificate, (short)0, len);
        certificate_length = len;
        JCSystem.commitTransaction();
    }

    protected final void setGenerationDate(final byte[] buf, final short off, final short len) {
        if(len != Constants.GENERATION_DATE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }
        Util.arrayCopy(buf, off, generation_date, (short)0, len);
    }

    protected final void setAttributes(final ECCurves ec,
                                       final byte[] buf, final short off, final short len) {
        if((len < Constants.ALGORITHM_ATTRIBUTES_MIN_LENGTH) ||
           (len > Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        switch(buf[off]) {
        case 0x01:
            if((len != 6) || is_secure_messaging_key) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if((Util.getShort(buf, (short)(off + 1)) < 2048) ||
               (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
               (buf[(short)(off + 5)] < 0) || (buf[(short)(off + 5)] > 3)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            break;

        case 0x12:
        case 0x13:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            final byte delta = (buf[(short)(len - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
            final ECParams params = ec.findByOid(buf, (short)(off + 1), (byte)(len - 1 - delta));
            if(params == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if((buf[0] != 0x12) && is_secure_messaging_key) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        JCSystem.beginTransaction();
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, attributes, (short)0, len);
        attributes_length = (byte)len;
        JCSystem.commitTransaction();
    }


    protected final boolean isRsa() {
        return (attributes[0] == 1);
    }

    protected final short rsaModulusBitSize() {
        return Util.getShort(attributes, (short)1);
    }

    protected final short rsaExponentBitSize() {
        return Util.getShort(attributes, (short)3);
    }

    protected final boolean isEc() {
        return ((attributes[0] == (byte)0x12) ||
                (attributes[0] == (byte)0x13));
    }

    protected final ECParams ecParams(final ECCurves ec) {
        final byte delta = (attributes[(short)(attributes_length - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
        return ec.findByOid(attributes, (short)1, (byte)(attributes_length - 1 - delta));
    }


    private final KeyPair generateRSA() {
        final PrivateKey priv = (PrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, rsaModulusBitSize(), false);
        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rsaModulusBitSize(), false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        pub.setExponent(Constants.RSA_EXPONENT, (short)0, (byte)Constants.RSA_EXPONENT.length);

        return new KeyPair(pub, priv);
    }


    private final KeyPair generateEC(final ECCurves ec) {

        final ECParams params = ecParams(ec);

        final ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, params.nb_bits, false);
        final ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, params.nb_bits, false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        return new KeyPair(pub, priv);
    }


    protected final void generate(final ECCurves ec) {

        KeyPair nkeys = null;

        if(isRsa()) {
            nkeys = generateRSA();
        } else if(isEc()) {
            nkeys = generateEC(ec);
        }

        if(nkeys == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        nkeys.genKeyPair();

        if(!nkeys.getPublic().isInitialized() || !nkeys.getPrivate().isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        keys = nkeys;
    }


    private final KeyPair importRSAKey(final byte[] buf,
                                       final short boff, final short len,
                                       final byte tag_count, final byte[] tag_val, final short[] tag_len) {

        final short attr_modulus_bit_size = rsaModulusBitSize();
        final short attr_modulus_byte_size = Common.bitsToBytes(attr_modulus_bit_size);

        final RSAPrivateCrtKey priv = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, attr_modulus_bit_size, false);
        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, attr_modulus_bit_size, false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x91:
                if(tag_len[i] != Common.bitsToBytes(rsaExponentBitSize())) {
                    return null;
                }
                pub.setExponent(buf, off, tag_len[i]);
                break;

            case (byte)0x92:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setP(buf, off, tag_len[i]);
                break;

            case (byte)0x93:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setQ(buf, off, tag_len[i]);
                break;

            case (byte)0x94:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setPQ(buf, off, tag_len[i]);
                break;

            case (byte)0x95:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDP1(buf, off, tag_len[i]);
                break;

            case (byte)0x96:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDQ1(buf, off, tag_len[i]);
                break;

            case (byte)0x97:
                if(tag_len[i] != attr_modulus_byte_size) {
                    return null;
                }
                pub.setModulus(buf, off, tag_len[i]);
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if(!priv.isInitialized() || !pub.isInitialized()) {
            return null;
        }

        return new KeyPair(pub, priv);
    }

    private final KeyPair importECKey(final ECCurves ec,
                                      final byte[] buf,
                                      final short boff, final short len,
                                      final byte tag_count, final byte[] tag_val, final short[] tag_len) {
        final ECParams params = ecParams(ec);

        final ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                                    params.nb_bits,
                                                                    false);
        final ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                                                                 params.nb_bits,
                                                                 false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x92:
                if(tag_len[i] > Common.bitsToBytes(params.nb_bits)) {
                    return null;
                }
                priv.setS(buf, off, tag_len[i]);
                break;

            case (byte)0x99:
                if(tag_len[i] > (short)(2 * Common.bitsToBytes(params.nb_bits) + 1)) {
                    return null;
                }
                if(((byte)(tag_len[i] - 1) & (byte)0x1) != 0) {
                    return null;
                }
                pub.setW(buf, off, tag_len[i]);
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if(!priv.isInitialized() || !pub.isInitialized()) {
            return null;
        }

        return new KeyPair(pub, priv);
    }

    protected final void importKey(final ECCurves ec,
                                   final byte[] buf, final short boff, final short len) {

        short off = boff;

        short template_len = 0;
        short template_off = 0;

        short data_len = 0;
        short data_off = 0;

        byte data_tag_count = 0;
        byte[] data_tag_val = new byte[7];
        short[] data_tag_len = new short[7];

        while((short)(len - (short)(off - boff)) > 2) {
            switch(Util.getShort(buf, off)) {

            case (short)0x7f48:
                off += 2;
                template_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                template_off = off;

                if(template_len > (short)(len - ((short)off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                while((short)(template_len - (short)(off - template_off)) > 1) {
                    if((buf[off] < (byte)0x91) ||
                       (buf[off] > (byte)0x99)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    if(data_tag_count >= data_tag_val.length) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    data_tag_val[data_tag_count] = buf[off];
                    ++off;

                    data_tag_len[data_tag_count] = Common.readLength(buf, off, (short)(template_len - (short)(off - template_off)));
                    off = Common.skipLength(buf, off, (short)(template_len - (short)(off - template_off)));

                    ++data_tag_count;
                }
                break;

            case (short)0x5f48:
                off += 2;
                data_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                data_off = off;

                if(data_len > (short)(len - ((short)off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                off += data_len;

                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
        }

        KeyPair nkeys = null;

        if(isRsa()) {
            nkeys = importRSAKey(buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
        } else if(isEc()) {
            nkeys = importECKey(ec, buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
        }

        if(nkeys == null) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        if(!nkeys.getPrivate().isInitialized() || !nkeys.getPublic().isInitialized()) {
            return;
        }

        resetKeys(false);
        keys = nkeys;
    }


    protected final short writePublicKeyDo(final byte[] buf, short off) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        final PublicKey pub = keys.getPublic();

        off = Util.setShort(buf, off, (short)0x7f49);

        if(isRsa()) {

            final RSAPublicKey rsapub = (RSAPublicKey)pub;
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());
            final short exponent_size = Common.bitsToBytes(rsaExponentBitSize());

            final short mlensize = (short)((modulus_size > (short)0xff) ? 3 : 2);

            final short flen =
                (short)(1 + mlensize + modulus_size +
                        1 + 1 + exponent_size);

            off = Common.writeLength(buf, off, flen);

            buf[off++] = (byte)0x81;
            off = Common.writeLength(buf, off, modulus_size);
            off += rsapub.getModulus(buf, off);

            buf[off++] = (byte)0x82;
            off = Common.writeLength(buf, off, exponent_size);
            off += rsapub.getExponent(buf, off);

            return off;

        } else if(isEc()) {

            final ECPublicKey ecpub = (ECPublicKey)pub;
            final short qsize = (short)(1 + 2 * (short)((ecpub.getSize() / 8) + (((ecpub.getSize() % 8) == 0) ? 0 : 1)));
            short rsize = (short)(1 + qsize);

            if(qsize > 0x7f) {
                rsize = (short)(rsize + 2);
            } else {
                rsize = (short)(rsize + 1);
            }

            off = Common.writeLength(buf, off, rsize);

            buf[off++] = (byte)0x86;

            off = Common.writeLength(buf, off, qsize);

            off += ecpub.getW(buf, off);

            return off;

        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return off;
    }




    protected final short sign(final byte[] buf, final short lc,
                               final boolean forAuth) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        final PrivateKey priv = keys.getPrivate();

        short off = 0;

        byte[] sha_header = null;

        if(isRsa()) {

            if(!forAuth) {
                if(lc == (short)(2 + Constants.DSI_SHA224_HEADER[1])) {
                    sha_header = Constants.DSI_SHA224_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA256_HEADER[1])) {
                    sha_header = Constants.DSI_SHA256_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA384_HEADER[1])) {
                    sha_header = Constants.DSI_SHA384_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA512_HEADER[1])) {
                    sha_header = Constants.DSI_SHA512_HEADER;
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }

                if(Util.arrayCompare(buf, (short)0, sha_header, (short)0, (byte)sha_header.length) != 0) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }
            }

            if(lc > (short)(((short)(Common.bitsToBytes(rsaModulusBitSize()) * 2)) / 5)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            cipher_rsa_pkcs1.init(priv, Cipher.MODE_ENCRYPT);

            off = cipher_rsa_pkcs1.doFinal(buf, (short)0, lc,
                                           buf, (short)lc);

            return Util.arrayCopyNonAtomic(buf, (short)lc,
                                           buf, (short)0,
                                           off);

        } else if(isEc()) {

            byte alg;

            if(lc == MessageDigest.LENGTH_SHA) {
                alg = Signature.ALG_ECDSA_SHA;
            } else if(lc == MessageDigest.LENGTH_SHA_224) {
                alg = Signature.ALG_ECDSA_SHA_224;
            } else if(lc == MessageDigest.LENGTH_SHA_256) {
                alg = Signature.ALG_ECDSA_SHA_256;
            } else if(lc == MessageDigest.LENGTH_SHA_384) {
                alg = Signature.ALG_ECDSA_SHA_384;
            } else if(lc == MessageDigest.LENGTH_SHA_512) {
                alg = Signature.ALG_ECDSA_SHA_512;
            } else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            final Signature sig = Signature.getInstance(alg, false);
            sig.init(priv, Signature.MODE_SIGN);

            final short sig_size = sig.signPreComputedHash(buf, (short)0, lc,
                                                           buf, lc);

            off = (short)(lc + 1);
            if((buf[off] & (byte)0x80) != (byte)0) {
                ++off;
            }
            ++off;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short r_size = Util.makeShort((byte)0, buf[off++]);
            final short r_off = off;

            off += r_size;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short s_size = Util.makeShort((byte)0, buf[off++]);
            final short s_off = off;

            off = (short)(lc + sig_size);

            if(r_size < s_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(s_size - r_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, r_off,
                                          buf, off, r_size);

            if(s_size < r_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(r_size - s_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, s_off,
                                          buf, off, s_size);

            off = Util.arrayCopyNonAtomic(buf, (short)(lc + sig_size),
                                          buf, (short)0,
                                          (short)(off - lc - sig_size));

            Util.arrayFillNonAtomic(buf, off, (short)(lc + sig_size - off), (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }


    protected final short decipher(final ECCurves ec, final byte[] buf, final short lc) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        final PrivateKey priv = keys.getPrivate();

        short off = 0;

        if(isRsa()) {
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());

            if(lc != (short)(modulus_size + 1)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[0] != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            cipher_rsa_pkcs1.init(priv, Cipher.MODE_DECRYPT);

            final short len = cipher_rsa_pkcs1.doFinal(buf, (short)1, (short)(lc - 1),
                                                       buf, (short)lc);

            off = Util.arrayCopyNonAtomic(buf, lc,
                                          buf, (short)0,
                                          len);

            Util.arrayFillNonAtomic(buf, lc, len, (byte)0);

            return off;

        } else if(isEc()) {

            final ECParams params = ecParams(ec);
            short elc = 7;

            if(params.nb_bits >= (short)512) {
                elc = 10;
            }

            if(lc != (short)(elc + 1 + (short)(2 * Common.bitsToBytes(params.nb_bits)))) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if(buf[off] != (byte)0xA6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(Util.getShort(buf, off) != (short)(0x7f49)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            off += 2;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[off] != (byte)0x86) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            final KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
            ka.init(priv);

            final short len  = ka.generateSecret(buf, off, (short)(lc - off),
                                                 buf, lc);

            off = Util.arrayCopyNonAtomic(buf, lc,
                                          buf, (short)0,
                                          len);

            Util.arrayFillNonAtomic(buf, lc, len, (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    protected final void initSignature(final Signature sign) {
        if(!isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        sign.init(keys.getPrivate(), Signature.MODE_SIGN);
    }

    protected final void initKeyAgreement(final KeyAgreement ka) {
        if(!isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        ka.init(keys.getPrivate());
    }

}
