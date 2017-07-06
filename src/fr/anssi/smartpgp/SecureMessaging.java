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

public final class SecureMessaging {

    public static final short MAC_LENGTH = (short)(Constants.AES_BLOCK_SIZE / (short)2);


    protected static final byte[] PADDING_BLOCK = {
        (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    private final byte[] iv;
    private final byte[] mac_chaining;

    private final Cipher cipher;

    private final CmacSignature macer;
    private AESKey senc;
    private CmacKey smac;
    private CmacKey srmac;

    protected final PGPKey static_key;

    protected SecureMessaging(final Transients transients) {
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        macer = new CmacSignature();

        iv = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE,
                                              JCSystem.CLEAR_ON_DESELECT);

        mac_chaining = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE,
                                                       JCSystem.CLEAR_ON_DESELECT);

        senc = null;
        smac = null;
        srmac = null;

        static_key = new PGPKey(true);

        reset(transients);
    }

    protected final void clearSession(final Transients transients) {
        if(senc != null) {
            senc.clearKey();
            senc = null;
        }
        if(smac != null) {
            smac.clearKey();
            smac = null;
        }
        if(srmac != null) {
            srmac.clearKey();
            srmac = null;
        }
        macer.clear();
        transients.setSecureMessagingEncryptionCounter((short)0);
        Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);
        Util.arrayFillNonAtomic(mac_chaining, (short)0, (short)mac_chaining.length, (byte)0);
    }

    protected final void reset(final Transients transients) {
        clearSession(transients);
        static_key.reset();
    }

    protected final boolean isInitialized() {
        return static_key.isInitialized();
    }

    protected final boolean isSessionAvailable() {
        return isInitialized()
            && (senc != null) && senc.isInitialized()
            && (smac != null) && smac.isInitialized()
            && (srmac != null) && srmac.isInitialized();
    }

    private static final byte aesKeyLength(final ECParams params) {
        if(params.nb_bits < (short)512) {
            return (byte)16;
        } else {
            return (byte)32;
        }
    }

    private final short scp11b(final ECParams params,
                               final byte[] buf, final short len) {

        final byte[] crt = new byte[]{ (byte)0xA6, (byte)0x0D,
                                       (byte)0x90, (byte)0x02, (byte)0x11, (byte)0x00,
                                       (byte)0x95, (byte)0x01, (byte)0x3C,
                                       (byte)0x80, (byte)0x01, (byte)0x88,
                                       (byte)0x81, (byte)0x01 };

        if(len <= (short)((short)crt.length + 4)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        if(Util.arrayCompare(crt, (short)0,
                             buf, (short)0,
                             (short)crt.length) != (byte)0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        short off = (short)crt.length;

        if(buf[off] != aesKeyLength(params)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return 0;
        }
        ++off;

        if(Util.getShort(buf, off) != (short)0x5F49) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }
        off += 2;

        final short keylen = Common.readLength(buf, off, len);

        off = Common.skipLength(buf, off, len);

        if((short)(off + keylen) > len) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        if(keylen != (short)(2 * Common.bitsToBytes(params.nb_bits) + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        final ECPrivateKey eskcard =  (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                                        params.nb_bits,
                                                                        false);
        final ECPublicKey epkcard = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                                                                     params.nb_bits,
                                                                     false);

        params.setParams(eskcard);
        params.setParams(epkcard);

        final KeyPair ekcard = new KeyPair(epkcard, eskcard);

        ekcard.genKeyPair();

        if(!eskcard.isInitialized() ||
           !epkcard.isInitialized()) {
            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
            return 0;
        }

        final KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        ka.init(eskcard);

        short msglen = 0;

        msglen += ka.generateSecret(buf, off, keylen, buf, len);
        eskcard.clearKey();

        static_key.initKeyAgreement(ka);
        msglen += ka.generateSecret(buf, off, keylen, buf, (short)(len + msglen));

        Util.setShort(buf, (short)(len + msglen), (short)0);
        msglen += 2;

        short counter = 1;
        off = (short)(len + msglen);
        msglen += 2;

        buf[(short)(len + msglen)] = crt[(short)8];
        ++msglen;
        buf[(short)(len + msglen)] = crt[(short)11];
        ++msglen;
        buf[(short)(len + msglen)] = buf[crt.length];
        ++msglen;

        short keydata_len = 0;

        final MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        while(keydata_len < (short)(4 * buf[crt.length])) {
            Util.setShort(buf, off, counter);
            ++counter;

            keydata_len += digest.doFinal(buf, len, msglen,
                                          buf, (short)(len + msglen + keydata_len));
        }

        final CmacKey sreceiptmac = new CmacKey(aesKeyLength(params));
        sreceiptmac.setKey(buf, (short)(len + msglen));

        if(senc != null) {
            senc.clearKey();
            senc = null;
        }
        senc = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                           (short)(aesKeyLength(params) * 8),
                                           false);
        senc.setKey(buf, (short)(len + msglen + aesKeyLength(params)));

        if(smac != null) {
            smac.clearKey();
            smac = null;
        }
        smac = new CmacKey(aesKeyLength(params));
        smac.setKey(buf, (short)(len + msglen + 2 * aesKeyLength(params)));

        if(srmac != null) {
            srmac.clearKey();
            srmac = null;
        }
        srmac = new CmacKey(aesKeyLength(params));
        srmac.setKey(buf, (short)(len + msglen + 3 * aesKeyLength(params)));

        Util.arrayFillNonAtomic(buf, len, (short)(msglen + keydata_len), (byte)0);

        off = len;
        Util.setShort(buf, off, (short)0x5F49);
        off += 2;
        off = Common.writeLength(buf, off, (short)(2 * Common.bitsToBytes(params.nb_bits) + 1));
        off += epkcard.getW(buf, off);
        msglen = off;

        epkcard.clearKey();

        buf[off++] = (byte)0x86;
        buf[off++] = (byte)Constants.AES_BLOCK_SIZE;

        macer.init(sreceiptmac);
        macer.sign(buf, (short)0, msglen,
                   buf, off, Constants.AES_BLOCK_SIZE);
        sreceiptmac.clearKey();
        macer.clear();

        Util.arrayCopy(buf, off, mac_chaining, (short)0, Constants.AES_BLOCK_SIZE);

        off += Constants.AES_BLOCK_SIZE;

        msglen = (short)(off - len);

        Util.arrayCopy(buf, len, buf, (short)0, msglen);

        return msglen;
    }


    protected final short establish(final Transients transients,
                                    final ECCurves ec,
                                    final byte[] buf, final short len) {

        clearSession(transients);

        if(isInitialized() && static_key.isEc()) {
            final ECParams params = static_key.ecParams(ec);

            if(params != null) {
                return scp11b(params, buf, len);
            }
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }



    private final void incrementEncryptionCounter(final Transients transients) {
        final short pval = transients.secureMessagingEncryptionCounter();
        final short nval = (short)(pval + 1);

        if(nval <= pval) {
            clearSession(transients);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        transients.setSecureMessagingEncryptionCounter(nval);
    }



    protected final short verifyAndDecryptCommand(final Transients transients,
                                                  short dataLen, short dataWithHeaderLen) {

        if(!isSessionAvailable()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }

        incrementEncryptionCounter(transients);

        if(dataLen < MAC_LENGTH) {
            clearSession(transients);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }

        final byte[] buf = transients.buffer;

        macer.init(smac);
        macer.update(mac_chaining, (short)0, Constants.AES_BLOCK_SIZE);
        macer.update(buf, dataLen, (short)(dataWithHeaderLen - dataLen));
        macer.sign(buf, (short)0, (short)(dataLen - MAC_LENGTH),
                   buf, dataLen, Constants.AES_BLOCK_SIZE);

        if(Util.arrayCompare(buf, (short)(dataLen - MAC_LENGTH),
                             buf, dataLen,
                             MAC_LENGTH) != (byte)0) {
            clearSession(transients);
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }

        Util.arrayCopyNonAtomic(buf, dataLen,
                                mac_chaining, (short)0,
                                Constants.AES_BLOCK_SIZE);

        dataLen -= MAC_LENGTH;

        if(dataLen > 0) {
            Util.arrayFillNonAtomic(buf, dataLen, Constants.AES_BLOCK_SIZE, (byte)0);
            Util.setShort(buf, (short)(dataLen + Constants.AES_BLOCK_SIZE - 2),
                          transients.secureMessagingEncryptionCounter());

            cipher.init(senc, Cipher.MODE_ENCRYPT);
            cipher.doFinal(buf, dataLen, Constants.AES_BLOCK_SIZE,
                           iv, (short)0);

            cipher.init(senc, Cipher.MODE_DECRYPT,
                        iv, (short)0, Constants.AES_BLOCK_SIZE);


            short tmp = (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - dataLen);
            if(tmp < Constants.AES_BLOCK_SIZE) {
                ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
                return 0;
            }

            Util.arrayCopyNonAtomic(buf, (short)0,
                                    buf, tmp,
                                    dataLen);
            dataLen = 0;
            while(tmp < Constants.INTERNAL_BUFFER_MAX_LENGTH) {
                if((short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - tmp) <= Constants.AES_BLOCK_SIZE) {
                    dataLen += cipher.doFinal(buf, tmp, (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - tmp),
                                              buf, dataLen);
                    tmp = Constants.INTERNAL_BUFFER_MAX_LENGTH;
                } else {
                    dataLen += cipher.update(buf, tmp, Constants.AES_BLOCK_SIZE,
                                             buf, dataLen);
                    tmp += Constants.AES_BLOCK_SIZE;
                }
            }

            Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);

            --dataLen;
            while((dataLen > 0) && buf[dataLen] == (byte)0)
                --dataLen;

            if((dataLen <= 0) || (buf[dataLen] != (byte)0x80)) {
                clearSession(transients);
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return 0;
            }

        }

        return dataLen;
    }



    protected final short encryptAndSign(final Transients transients,
                                         short dataLen,
                                         final short sw) {

        if(!isSessionAvailable()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return 0;
        }

        final byte[] buf = transients.buffer;

        if(dataLen > 0) {
            Util.arrayFillNonAtomic(buf, dataLen, Constants.AES_BLOCK_SIZE, (byte)0);
            buf[dataLen] = (byte)0x80;
            Util.setShort(buf, (short)(dataLen + Constants.AES_BLOCK_SIZE - 2),
                          transients.secureMessagingEncryptionCounter());

            cipher.init(senc, Cipher.MODE_ENCRYPT);

            cipher.doFinal(buf, dataLen, Constants.AES_BLOCK_SIZE,
                           iv, (short)0);

            cipher.init(senc, Cipher.MODE_ENCRYPT,
                        iv, (short)0, Constants.AES_BLOCK_SIZE);

            short tmp = (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - dataLen);
            if(tmp < Constants.AES_BLOCK_SIZE) {
                ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
                return 0;
            }

            Util.arrayCopyNonAtomic(buf, (short)0,
                                    buf, tmp,
                                    dataLen);
            dataLen = 0;
            while(tmp < Constants.INTERNAL_BUFFER_MAX_LENGTH) {
                if((short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - tmp) <= Constants.AES_BLOCK_SIZE) {
                    dataLen += cipher.doFinal(buf, tmp, (short)(Constants.INTERNAL_BUFFER_MAX_LENGTH - tmp),
                                              buf, dataLen);
                    tmp = Constants.INTERNAL_BUFFER_MAX_LENGTH;
                } else {
                    dataLen += cipher.update(buf, tmp, Constants.AES_BLOCK_SIZE,
                                             buf, dataLen);
                    tmp += Constants.AES_BLOCK_SIZE;
                }
            }

            Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);
        }

        macer.init(srmac);

        macer.update(mac_chaining, (short)0, Constants.AES_BLOCK_SIZE);
        if(dataLen > 0) {
            macer.update(buf, (short)0, dataLen);
        }
        macer.updateShort(sw);
        dataLen += macer.sign(null, (short)0, (short)0,
                              buf, dataLen, MAC_LENGTH);

        return dataLen;
    }

}
