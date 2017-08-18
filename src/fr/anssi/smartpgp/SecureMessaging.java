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

    private static final byte[] CRT_PREFIX = {
        (byte)0xA6, (byte)0x0D,
        (byte)0x90, (byte)0x02, (byte)0x11, (byte)0x00,
        (byte)0x95, (byte)0x01, (byte)0x3C,
        (byte)0x80, (byte)0x01, (byte)0x88,
        (byte)0x81, (byte)0x01
    };

    private final MessageDigest digest;
    private final KeyAgreement key_agreement;

    protected final PGPKey static_key;

    private final Cipher cipher;
    private AESKey senc;
    private final byte[] iv;

    private final CmacSignature macer;
    private final byte[] mac_chaining;
    private CmacKey sreceiptmac;
    private CmacKey smac;
    private CmacKey srmac;


    protected SecureMessaging(final Transients transients) {
        digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        key_agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        static_key = new PGPKey(true);

        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        senc = null;
        iv = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE,
                                             JCSystem.CLEAR_ON_DESELECT);

        macer = new CmacSignature();
        mac_chaining = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE,
                                                       JCSystem.CLEAR_ON_DESELECT);
        sreceiptmac = null;
        smac = null;
        srmac = null;

        reset(true, transients);
    }


    protected final void clearSession(final Transients transients) {
        if((senc != null) && senc.isInitialized()) {
            senc.clearKey();
        }
        Util.arrayFillNonAtomic(iv, (short)0, (short)iv.length, (byte)0);

        macer.clear();
        Util.arrayFillNonAtomic(mac_chaining, (short)0, (short)mac_chaining.length, (byte)0);
        if((sreceiptmac != null) && senc.isInitialized()) {
            sreceiptmac.clearKey();
        }
        if((smac != null) && smac.isInitialized()) {
            smac.clearKey();
        }
        if((srmac != null) && srmac.isInitialized()) {
            srmac.clearKey();
        }

        transients.setSecureMessagingEncryptionCounter((short)0);
    }

    protected final void reset(final boolean isRegistering, final Transients transients) {
        clearSession(transients);
        sreceiptmac = null;
        senc = null;
        smac = null;
        srmac = null;
        static_key.reset(isRegistering);
    }

    private final void initSession(final short keyLength,
                                   final byte[] buf, final short off) {
        if((sreceiptmac == null) ||
           (sreceiptmac.getSize() != (short)(keyLength * 8))) {
            senc = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                               (short)(keyLength * 8),
                                               false);

            sreceiptmac = new CmacKey(keyLength);
            smac = new CmacKey(keyLength);
            srmac = new CmacKey(keyLength);
        }

        sreceiptmac.setKey(buf, off);
        senc.setKey(buf, (short)(off + keyLength));
        smac.setKey(buf, (short)(off + (short)(2 * keyLength)));
        srmac.setKey(buf, (short)(off + (short)(3 * keyLength)));
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


    private final short scp11b(final ECCurves curves,
                               final byte[] buf, final short len) {

        final ECParams params = static_key.ecParams(curves);

        if(len <= (short)((short)CRT_PREFIX.length + 4)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        if(Util.arrayCompare(CRT_PREFIX, (short)0,
                             buf, (short)0,
                             (short)CRT_PREFIX.length) != (byte)0) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        short off = (short)CRT_PREFIX.length;

        if(buf[off] != Common.aesKeyLength(params)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return 0;
        }
        ++off;

        if(Util.getShort(buf, off) != (short)0x5F49) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }
        off += 2;

        short keylen = Common.readLength(buf, off, len);

        off = Common.skipLength(buf, off, len);

        if((short)(off + keylen) > len) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        if(keylen != (short)(2 * Common.bitsToBytes(params.nb_bits) + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        ECPrivateKey eskcard = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                                 params.nb_bits,
                                                                 false);
        ECPublicKey epkcard = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                                                               params.nb_bits,
                                                               false);

        params.setParams(eskcard);
        params.setParams(epkcard);

        KeyPair ekcard = new KeyPair(epkcard, eskcard);

        ekcard.genKeyPair();

        if(!eskcard.isInitialized() ||
           !epkcard.isInitialized()) {
            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
            return 0;
        }

        key_agreement.init(eskcard);

        short msglen = 0;

        msglen += key_agreement.generateSecret(buf, off, keylen, buf, len);
        eskcard.clearKey();
        eskcard = null;

        static_key.initKeyAgreement(key_agreement);
        msglen += key_agreement.generateSecret(buf, off, keylen, buf, (short)(len + msglen));

        Util.setShort(buf, (short)(len + msglen), (short)0);
        msglen += 2;

        short counter = 1;
        off = (short)(len + msglen);
        msglen += 2;

        buf[(short)(len + msglen)] = CRT_PREFIX[(short)8];
        ++msglen;
        buf[(short)(len + msglen)] = CRT_PREFIX[(short)11];
        ++msglen;
        buf[(short)(len + msglen)] = buf[CRT_PREFIX.length];
        ++msglen;

        keylen = 0;

        while(keylen < (short)(4 * buf[CRT_PREFIX.length])) {
            Util.setShort(buf, off, counter);
            ++counter;

            keylen += digest.doFinal(buf, len, msglen,
                                     buf, (short)(len + msglen + keylen));
        }

        initSession(Common.aesKeyLength(params), buf, (short)(len + msglen));

        Util.arrayFillNonAtomic(buf, len, (short)(msglen + keylen), (byte)0);

        off = len;
        Util.setShort(buf, off, (short)0x5F49);
        off += 2;
        off = Common.writeLength(buf, off, (short)(2 * Common.bitsToBytes(params.nb_bits) + 1));
        off += epkcard.getW(buf, off);
        msglen = off;

        epkcard.clearKey();
        epkcard = null;

        ekcard = null;

        buf[off++] = (byte)0x86;
        buf[off++] = (byte)Constants.AES_BLOCK_SIZE;

        macer.init(sreceiptmac);
        macer.sign(buf, (short)0, msglen,
                   buf, off, Constants.AES_BLOCK_SIZE);
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
            return scp11b(ec, buf, len);
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
