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

public final class SmartPGPApplet extends Applet {

    private final ECCurves ec;
    private final Persistent data;
    private final SecureMessaging sm;

    private final Transients transients;

    private final Cipher cipher_aes_cbc_nopad;
    private final RandomData random_data;

    public SmartPGPApplet() {
        cipher_aes_cbc_nopad = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        random_data = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        ec = new ECCurves();

        data = new Persistent();
        transients = new Transients();
        sm = new SecureMessaging(transients);
    }

    public static final void install(byte[] buf, short off, byte len) {
        new SmartPGPApplet().register();
    }

    private final PGPKey currentTagOccurenceToKey() {
        switch(transients.currentTagOccurrence()) {
        case 0:
            return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
        case 1:
            return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
        case 2:
            return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
        case 3:
            return sm.static_key;
        default:
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return null;
        }
    }

    private final void prepareChainingInput(final byte[] apdubuf) {
        short tmp;

        tmp = transients.outputLength();
        if(tmp > 0) {
            Util.arrayFillNonAtomic(transients.buffer, transients.outputStart(), tmp, (byte)0);
        }
        transients.setChainingOutput(false);
        transients.setOutputStart((short)0);
        transients.setOutputLength((short)0);

        if(transients.chainingInput()) {
            if((apdubuf[ISO7816.OFFSET_INS] != transients.chainingInputIns()) ||
               (apdubuf[ISO7816.OFFSET_P1] != transients.chainingInputP1()) ||
               (apdubuf[ISO7816.OFFSET_P2] != transients.chainingInputP2())) {
                transients.setChainingInput(false);
                transients.setChainingInputLength((short)0);
                ISOException.throwIt(Constants.SW_CHAINING_ERROR);
                return;
            }
            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING) {
                transients.setChainingInput(false);
            }
        } else {
            tmp = transients.chainingInputLength();
            if(tmp > 0) {
                Util.arrayFillNonAtomic(transients.buffer, (short)0, tmp, (byte)0);
            }
            transients.setChainingInputLength((short)0);

            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {
                transients.setChainingInputIns(apdubuf[ISO7816.OFFSET_INS]);
                transients.setChainingInputP1(apdubuf[ISO7816.OFFSET_P1]);
                transients.setChainingInputP2(apdubuf[ISO7816.OFFSET_P2]);
                transients.setChainingInput(true);
            }
        }
    }

    private final void receiveData(final APDU apdu) {
        final byte[] apdubuf = apdu.getBuffer();

        short blen = apdu.setIncomingAndReceive();

        final short lc = apdu.getIncomingLength();
        final short offcdata = apdu.getOffsetCdata();

        short off = transients.chainingInputLength();

        if((short)(off + lc) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
            transients.setChainingInput(false);
            transients.setChainingInputLength((short)0);
            ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
            return;
        }

        while(blen > 0) {
            off = Util.arrayCopyNonAtomic(apdubuf, offcdata,
                                          transients.buffer, off,
                                          blen);
            blen = apdu.receiveBytes(offcdata);
        }

        transients.setChainingInputLength(off);
    }

    private final void sensitiveData() {
        final byte proto = APDU.getProtocol();

        if(((proto & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A) ||
           ((proto & APDU.PROTOCOL_MEDIA_MASK) == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B)) {
            if(sm.isInitialized() && !transients.secureMessagingOk()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }
    }

    private final void assertAdmin() {
        if(!data.admin_pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private final void assertUserMode81() {
        if(!data.user_pin.isValidated() || !transients.userPinMode81()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private final void assertUserMode82() {
        if(!data.user_pin.isValidated() || !transients.userPinMode82()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private final short writePwStatus(final byte[] buf, short off) {
        buf[off++] = (byte)(data.user_pin_force_verify_signature ? 0x00 : 0x01);

        if(data.user_pin_is_format_2) {
            buf[off++] = (byte)0x80 | Constants.USER_PIN_MAX_SIZE_FORMAT_2;
        } else {
            buf[off++] = Constants.USER_PIN_MAX_SIZE;
        }
        if(data.user_puk_is_format_2) {
            buf[off++] = (byte)0x80 | Constants.USER_PUK_MAX_SIZE_FORMAT_2;
        } else {
            buf[off++] = Constants.USER_PUK_MAX_SIZE;
        }
        if(data.admin_pin_is_format_2) {
            buf[off++] = (byte)0x80 | Constants.ADMIN_PIN_MAX_SIZE_FORMAT_2;
        } else {
            buf[off++] = Constants.ADMIN_PIN_MAX_SIZE;
        }

        buf[off++] = data.user_pin.getTriesRemaining();
        if(data.user_puk_length > 0) {
            buf[off++] = data.user_puk.getTriesRemaining();
        } else {
            buf[off++] = (byte)0x00;
        }
        buf[off++] = data.admin_pin.getTriesRemaining();

        return off;
    }

    private final short writeKeyFingerprints(final byte[] buf, short off) {
        for(byte i = 0; i < data.pgp_keys.length; ++i) {
            off = data.pgp_keys[i].fingerprint.write(buf, off);
        }
        return off;
    }

    private final short writeCaFingerprints(final byte[] buf, short off) {
        for(byte i = 0; i < data.fingerprints.length; ++i) {
            off = data.fingerprints[i].write(buf, off);
        }
        return off;
    }

    private final short writeKeyGenerationDates(final byte[] buf, short off) {
        for(byte i = 0; i < data.pgp_keys.length; ++i) {
            off = Util.arrayCopyNonAtomic(data.pgp_keys[i].generation_date, (short)0,
                                          buf, off,
                                          Constants.GENERATION_DATE_SIZE);
        }
        return off;
    }

    private final void processSelectData(final short lc,
                                         final byte p1, final byte p2) {
        if((lc < 5) || (lc > 6)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        if((p1 < 0) || (p1 > 3) ||
           (p2 != 0x04)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        final byte[] buf = transients.buffer;

        if((buf[0] != (byte)0x60) ||
           (buf[1] != (byte)(lc - 2)) ||
           (buf[2] != (byte)0x5C) ||
           (buf[3] != (byte)(lc - 2 - 2))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        transients.setCurrentTagOccurrence(p1);

        if(buf[3] == 1) {
            transients.setCurrentTag(buf[4]);
        } else if(buf[3] == 2) {
            transients.setCurrentTag(Util.getShort(buf, (short)4));
        }
    }

    private final short processGetData(final byte p1, final byte p2) {

        final short tag = Util.makeShort(p1, p2);
        short off = 0;
        short tlen = 0;

        if(transients.currentTag() == 0) {
            transients.setCurrentTag(tag);
            transients.setCurrentTagOccurrence((byte)0);
        } else if(transients.currentTag() != tag) {
            transients.setCurrentTagOccurrence((byte)0);
        }

        final byte[] buf = transients.buffer;
        PGPKey k;

        switch(tag) {
        case Constants.TAG_AID:
            off = (short)(off + JCSystem.getAID().getBytes(buf, off));
            break;

        case Constants.TAG_LOGIN:
            off = Util.arrayCopyNonAtomic(data.login, (short)0, buf, off, data.login_length);
            break;

        case Constants.TAG_URL:
            off = Util.arrayCopyNonAtomic(data.url, (short)0, buf, off, data.url_length);
            break;

        case Constants.TAG_PRIVATE_DO_0101:
            off = Util.arrayCopyNonAtomic(data.do_0101, (short)0, buf, off, data.do_0101_length);
            break;

        case Constants.TAG_PRIVATE_DO_0102:
            off = Util.arrayCopyNonAtomic(data.do_0102, (short)0, buf, off, data.do_0102_length);
            break;

        case Constants.TAG_PRIVATE_DO_0103:
            assertUserMode82();
            off = Util.arrayCopyNonAtomic(data.do_0103, (short)0, buf, off, data.do_0103_length);
            break;

        case Constants.TAG_PRIVATE_DO_0104:
            assertAdmin();
            off = Util.arrayCopyNonAtomic(data.do_0104, (short)0, buf, off, data.do_0104_length);
            break;

        case Constants.TAG_KEY_FINGERPRINTS:
            off = writeKeyFingerprints(buf, off);
            break;

        case Constants.TAG_CA_FINGERPRINTS:
            off = writeCaFingerprints(buf, off);
            break;
        case Constants.TAG_KEY_GENERATION_DATES:
            off = writeKeyGenerationDates(buf, off);
            break;

        case Constants.TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES:
            off = Util.arrayCopyNonAtomic(Constants.HISTORICAL_BYTES, (short)0,
                                          buf, (short)off,
                                          (byte)Constants.HISTORICAL_BYTES.length);
            break;

        case Constants.TAG_CARDHOLDER_RELATED_DATA:
            buf[off++] = (byte)0x5B;
            off = Common.writeLength(buf, off, data.name_length);
            off = Util.arrayCopyNonAtomic(data.name, (short)0, buf, off, data.name_length);

            off = Util.setShort(buf, off, (short)0x5f2d);
            off = Common.writeLength(buf, off, data.lang_length);
            off = Util.arrayCopyNonAtomic(data.lang, (short)0, buf, off, data.lang_length);

            off = Util.setShort(buf, off, (short)0x5f35);
            buf[off++] = (byte)0x01;
            buf[off++] = data.sex;
            break;

        case Constants.TAG_EXTENDED_LENGTH_INFORMATION:
            off = Util.setShort(buf, off, Constants.TAG_EXTENDED_LENGTH_INFORMATION);
            off = Common.writeLength(buf, off, (short)8);
            buf[off++] = (byte)0x02;
            buf[off++] = (byte)0x02;
            off = Util.setShort(buf, off, Constants.APDU_MAX_LENGTH);
            buf[off++] = (byte)0x02;
            buf[off++] = (byte)0x02;
            off = Util.setShort(buf, off, Constants.APDU_MAX_LENGTH);
            break;

        case Constants.TAG_ALGORITHM_ATTRIBUTES_SIG:
            buf[off++] = (byte)0xc1;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);
            break;

        case Constants.TAG_ALGORITHM_ATTRIBUTES_DEC:
            buf[off++] = (byte)0xc2;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);
            break;

        case Constants.TAG_ALGORITHM_ATTRIBUTES_AUT:
            buf[off++] = (byte)0xc3;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);
            break;

        case Constants.TAG_ALGORITHM_ATTRIBUTES_SM:
            buf[off++] = (byte)0xd4;
            k = sm.static_key;
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);
            break;

        case Constants.TAG_APPLICATION_RELATED_DATA:
            tlen = (short)(1 + 1 + Constants.EXTENDED_CAPABILITIES.length +
                           1 + 1 + data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].attributes_length +
                           1 + 1 + data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].attributes_length +
                           1 + 1 + data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].attributes_length +
                           1 + 1 + 7 +
                           1 + 1 + (3 * Constants.FINGERPRINT_SIZE) +
                           1 + 1 + (3 * Constants.FINGERPRINT_SIZE) +
                           1 + 1 + (3 * Constants.GENERATION_DATE_SIZE));

            final byte aid_length = JCSystem.getAID().getBytes(buf, off);

            buf[off++] = (byte)Constants.TAG_APPLICATION_RELATED_DATA;
            off = Common.writeLength(buf, off, (short)(tlen + 1 + aid_length + 2 + 1 + Constants.HISTORICAL_BYTES.length));

            buf[off++] = (byte)Constants.TAG_AID;
            off = Common.writeLength(buf, off, aid_length);
            off += JCSystem.getAID().getBytes(buf, off);
            off = Util.setShort(buf, off, Constants.TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES);
            off = Common.writeLength(buf, off, (short)Constants.HISTORICAL_BYTES.length);
            off = Util.arrayCopyNonAtomic(Constants.HISTORICAL_BYTES, (short)0,
                                          buf, off,
                                          (byte)Constants.HISTORICAL_BYTES.length);

            buf[off++] = (byte)0x73;
            off = Common.writeLength(buf, off, tlen);
            buf[off++] = (byte)0xc0;
            off = Common.writeLength(buf, off, (short)Constants.EXTENDED_CAPABILITIES.length);
            off = Util.arrayCopyNonAtomic(Constants.EXTENDED_CAPABILITIES, (short)0,
                                          buf, off,
                                          (short)Constants.EXTENDED_CAPABILITIES.length);

            buf[off++] = (byte)0xc1;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);

            buf[off++] = (byte)0xc2;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);

            buf[off++] = (byte)0xc3;
            k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
            off = Common.writeLength(buf, off, k.attributes_length);
            off = Util.arrayCopyNonAtomic(k.attributes, (short)0,
                                          buf, off,
                                          k.attributes_length);

            buf[off++] = (byte)0xc4;
            buf[off++] = 7;
            off = writePwStatus(buf, off);

            buf[off++] = (byte)0xc5;
            off = Common.writeLength(buf, off, (short)(3 * Constants.FINGERPRINT_SIZE));
            off = writeKeyFingerprints(buf, off);

            buf[off++] = (byte)0xc6;
            off = Common.writeLength(buf, off, (short)(3 * Constants.FINGERPRINT_SIZE));
            off = writeCaFingerprints(buf, off);

            buf[off++] = (byte)0xcd;
            off = Common.writeLength(buf, off, (short)(3 * Constants.GENERATION_DATE_SIZE));
            off = writeKeyGenerationDates(buf, off);

            Common.writeLength(buf, (short)1, (short)(off - 3));
            break;

        case Constants.TAG_PW_STATUS:
            off = writePwStatus(buf, off);
            break;

        case Constants.TAG_SECURITY_SUPPORT_TEMPLATE:
            buf[off++] = (byte)0x93;
            buf[off++] = (byte)data.digital_signature_counter.length;
            off = Util.arrayCopyNonAtomic(data.digital_signature_counter, (short)0,
                                          buf, off,
                                          (byte)data.digital_signature_counter.length);
            break;

        case Constants.TAG_CARDHOLDER_CERTIFICATE:
            k = currentTagOccurenceToKey();

            if(k == null) {
                ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                return 0;
            }

            off = Util.arrayCopyNonAtomic(k.certificate, (short)0,
                                          buf, off,
                                          k.certificate_length);
            break;

        case Constants.TAG_KEY_DERIVATION_FUNCTION:
            off = Util.arrayCopyNonAtomic(data.key_derivation_function, (short)0,
                                          buf, off,
                                          data.key_derivation_function_length);
            break;

        default:
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        return off;
    }

    private final short processGetNextData(final byte p1, final byte p2) {

        if(Util.makeShort(p1, p2) != Constants.TAG_CARDHOLDER_CERTIFICATE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return 0;
        }

        final PGPKey k = currentTagOccurenceToKey();

        if(k == null) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        transients.setCurrentTagOccurrence((byte)(transients.currentTagOccurrence() + 1));

        return Util.arrayCopyNonAtomic(k.certificate, (short)0,
                                       transients.buffer, (short)0,
                                       k.certificate_length);
    }

    private final void processVerify(short lc, final byte p1, final byte p2) {

        sensitiveData();

        if(p1 == 0) {

            if(lc == 0) {
                byte remaining = 0;

                switch(p2) {
                case (byte)0x81:
                    if(data.user_pin.isValidated() && transients.userPinMode81()) {
                        return;
                    }
                    remaining = data.user_pin.getTriesRemaining();
                    break;

                case (byte)0x82:
                    if(data.user_pin.isValidated() && transients.userPinMode82()) {
                        return;
                    }
                    remaining = data.user_pin.getTriesRemaining();
                    break;

                case (byte)0x83:
                    if(data.admin_pin.isValidated()) {
                        return;
                    }
                    remaining = data.admin_pin.getTriesRemaining();
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                    return;
                }

                remaining = (byte)((byte)0xf & remaining);
                ISOException.throwIt(Util.makeShort((byte)0x63, (byte)(0xC0 | remaining)));
                return;

            } else {

                switch(p2) {
                case (byte)0x81:
                case (byte)0x82:
                    if(data.user_pin_is_format_2) {
                        Common.checkPinFormat2(transients.buffer,
                                               (short)0, lc,
                                               Constants.USER_PIN_MIN_SIZE_FORMAT_2,
                                               Constants.USER_PIN_MAX_SIZE_FORMAT_2);
                    } else {
                        if((lc < Constants.USER_PIN_MIN_SIZE) ||
                           (lc > Constants.USER_PIN_MAX_SIZE)) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                            return;
                        }
                    }

                    if(p2 == (byte)0x81) {
                        transients.setUserPinMode81(false);
                    } else {
                        transients.setUserPinMode82(false);
                    }

                    if(!data.user_pin.check(transients.buffer, (short)0, (byte)lc)) {
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                        return;
                    }

                    if(p2 == (byte)0x81) {
                        transients.setUserPinMode81(true);
                    } else {
                        transients.setUserPinMode82(true);
                    }
                    return;

                case (byte)0x83:
                    if(data.admin_pin_is_format_2) {
                        Common.checkPinFormat2(transients.buffer,
                                               (short)0, lc,
                                               Constants.ADMIN_PIN_MIN_SIZE_FORMAT_2,
                                               Constants.ADMIN_PIN_MAX_SIZE_FORMAT_2);
                    } else {
                        if((lc < Constants.ADMIN_PIN_MIN_SIZE) ||
                           (lc > Constants.ADMIN_PIN_MAX_SIZE)) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                            return;
                        }
                    }

                    if(!data.admin_pin.check(transients.buffer, (short)0, (byte)lc)) {
                        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                        return;
                    }
                    return;

                default:
                    ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                    return;
                }
            }

        } else if(p1 == (byte)0xff) {

            if(lc != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return;
            }

            switch(p2) {
            case (byte)0x81:
                transients.setUserPinMode81(false);
                return;

            case (byte)0x82:
                transients.setUserPinMode82(false);
                return;

            case (byte)0x83:
                if(data.admin_pin.isValidated()) {
                    data.admin_pin.reset();
                }
                return;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
            }
        }

        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return;
    }

    private final void processChangeReferenceData(final short lc,
                                                  final byte p1, final byte p2) {

        sensitiveData();

        byte off;

        if(p1 != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        switch(p2) {
        case (byte)0x81:
            if(data.user_pin_is_format_2) {
                if(lc != (short)(2 * data.user_pin_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                Common.checkPinFormat2(transients.buffer,
                                       (short)0, data.user_pin_length,
                                       Constants.USER_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.USER_PIN_MAX_SIZE_FORMAT_2);
                Common.checkPinFormat2(transients.buffer,
                                       data.user_pin_length, data.user_pin_length,
                                       Constants.USER_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.USER_PIN_MAX_SIZE_FORMAT_2);
            } else {
                if((lc < (data.user_pin_length + Constants.USER_PIN_MIN_SIZE)) ||
                   (lc > (data.user_pin_length + Constants.USER_PIN_MAX_SIZE))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
            }
            off = data.user_pin_length;
            if(!data.user_pin.check(transients.buffer, (short)0, off)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            transients.setUserPinMode81(false);
            transients.setUserPinMode82(false);
            JCSystem.beginTransaction();
            data.user_pin_length = (byte)(lc - off);
            data.user_pin.update(transients.buffer, off, data.user_pin_length);
            JCSystem.commitTransaction();
            data.user_pin.resetAndUnblock();
            break;

        case (byte)0x83:
            if(data.admin_pin_is_format_2) {
                if(lc != (short)(2 * data.admin_pin_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                Common.checkPinFormat2(transients.buffer,
                                       (short)0, data.admin_pin_length,
                                       Constants.ADMIN_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.ADMIN_PIN_MAX_SIZE_FORMAT_2);
                Common.checkPinFormat2(transients.buffer,
                                       data.admin_pin_length, data.admin_pin_length,
                                       Constants.ADMIN_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.ADMIN_PIN_MAX_SIZE_FORMAT_2);
            } else {
                if((lc < (data.admin_pin_length + Constants.ADMIN_PIN_MIN_SIZE)) ||
                   (lc > (data.admin_pin_length + Constants.ADMIN_PIN_MAX_SIZE))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
            }
            off = data.admin_pin_length;
            if(!data.admin_pin.check(transients.buffer, (short)0, off)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            JCSystem.beginTransaction();
            data.admin_pin_length = (byte)(lc - off);
            data.admin_pin.update(transients.buffer, off, data.admin_pin_length);
            JCSystem.commitTransaction();
            data.admin_pin.resetAndUnblock();;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }
    }

    private final void processResetRetryCounter(final short lc,
                                                final byte p1, final byte p2) {

        sensitiveData();

        byte off = 0;

        if(p2 != (byte)0x81) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        switch(p1) {
        case (byte)0x00:
            if(data.user_pin_is_format_2) {
                if(lc != (short)(data.user_puk_length + data.user_pin_length)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                Common.checkPinFormat2(transients.buffer,
                                       data.user_puk_length, data.user_pin_length,
                                       Constants.USER_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.USER_PIN_MAX_SIZE_FORMAT_2);
            } else {
                if((lc < (data.user_puk_length + Constants.USER_PIN_MIN_SIZE)) ||
                   (lc > (data.user_puk_length + Constants.USER_PIN_MAX_SIZE))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
            }
            if(data.user_puk_is_format_2) {
                Common.checkPinFormat2(transients.buffer,
                                       (short)0, data.user_puk_length,
                                       Constants.USER_PUK_MIN_SIZE_FORMAT_2,
                                       Constants.USER_PUK_MAX_SIZE_FORMAT_2);
            }
            off = data.user_puk_length;
            if(!data.user_puk.check(transients.buffer, (short)0, off)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                return;
            }
            transients.setUserPinMode81(false);
            transients.setUserPinMode82(false);
            JCSystem.beginTransaction();
            data.user_pin_length = (byte)(lc - off);
            data.user_pin.update(transients.buffer, off, data.user_pin_length);
            JCSystem.commitTransaction();
            data.user_pin.resetAndUnblock();
            break;

        case (byte)0x02:
            assertAdmin();
            if(data.user_pin_is_format_2) {
                Common.checkPinFormat2(transients.buffer,
                                       (short)0, lc,
                                       Constants.USER_PIN_MIN_SIZE_FORMAT_2,
                                       Constants.USER_PIN_MAX_SIZE_FORMAT_2);
            } else {
                if((lc < Constants.USER_PIN_MIN_SIZE) ||
                   (lc > Constants.USER_PIN_MAX_SIZE)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
            }
            transients.setUserPinMode81(false);
            transients.setUserPinMode82(false);
            JCSystem.beginTransaction();
            data.user_pin_length = (byte)lc;
            data.user_pin.update(transients.buffer, (short)0, data.user_pin_length);
            JCSystem.commitTransaction();
            data.user_pin.resetAndUnblock();
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }
    }

    private final void processPutData(final short lc,
                                      final byte p1, final byte p2,
                                      final boolean isOdd) {

        sensitiveData();

        final byte[] buf = transients.buffer;

        PGPKey k = null;

        if(isOdd) {

            assertAdmin();

            if((p1 != (byte)0x3f) || (p2 != (byte)0xff)) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
            }
            if(lc < 6) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return;
            }

            if(buf[0] != (byte)0x4D) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }

            final short len = Common.readLength(buf, (byte)1, (short)(lc - 1));
            final short off = Common.skipLength(buf, (byte)1, (short)(lc - 1));

            if((short)(off + len) != lc) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return;
            }

            switch(Util.getShort(buf, off)) {
            case Constants.CRT_SIGNATURE_KEY:
                k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(data.digital_signature_counter,
                                        (short)0, (byte)data.digital_signature_counter.length,
                                        (byte)0);
                JCSystem.commitTransaction();
                break;

            case Constants.CRT_DECRYPTION_KEY:
                k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
                break;

            case Constants.CRT_AUTHENTICATION_KEY:
                k = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
                break;

            case Constants.CRT_SECURE_MESSAGING_KEY:
                k = sm.static_key;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }

            k.importKey(ec, buf, (short)(off + 2), (short)(lc - off - 2));

        } else {
            final short tag = Util.makeShort(p1, p2);

            if(transients.currentTag() == 0) {
                transients.setCurrentTag(tag);
                transients.setCurrentTagOccurrence((byte)0);
            } else if(transients.currentTag() != tag) {
                transients.setCurrentTagOccurrence((byte)0);
            }

            switch(tag) {
            case Constants.TAG_NAME:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.NAME_MAX_LENGTH)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.name_length > 0) {
                    Util.arrayFillNonAtomic(data.name, (short)0, data.name_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.name, (short)0, lc);
                data.name_length = (byte)lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_LOGIN:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.login_length > 0) {
                    Util.arrayFillNonAtomic(data.login, (short)0, data.login_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.login, (short)0, lc);
                data.login_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_LANG:
                assertAdmin();
                if((lc < Constants.LANG_MIN_LENGTH) ||
                   (lc > Constants.LANG_MAX_LENGTH)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.lang_length > 0) {
                    Util.arrayFillNonAtomic(data.lang, (short)0, data.lang_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.lang, (short)0, lc);
                data.lang_length = (byte)lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_SEX:
                assertAdmin();
                if(lc != 1) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }

                switch(buf[0]) {
                case Constants.SEX_MALE:
                case Constants.SEX_FEMALE:
                case Constants.SEX_NOT_ANNOUNCED:
                    data.sex = buf[0];
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }
                break;

            case Constants.TAG_URL:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.url_length > 0) {
                    Util.arrayFillNonAtomic(data.url, (short)0, data.url_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.url, (short)0, lc);
                data.url_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_PRIVATE_DO_0101:
                assertUserMode82();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.do_0101_length > 0) {
                    Util.arrayFillNonAtomic(data.do_0101, (short)0, data.do_0101_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.do_0101, (short)0, lc);
                data.do_0101_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_PRIVATE_DO_0102:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.do_0102_length > 0) {
                    Util.arrayFillNonAtomic(data.do_0102, (short)0, data.do_0102_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.do_0102, (short)0, lc);
                data.do_0102_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_PRIVATE_DO_0103:
                assertUserMode82();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.do_0103_length > 0) {
                    Util.arrayFillNonAtomic(data.do_0103, (short)0, data.do_0103_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.do_0103, (short)0, lc);
                data.do_0103_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_PRIVATE_DO_0104:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.do_0104_length > 0) {
                    Util.arrayFillNonAtomic(data.do_0104, (short)0, data.do_0104_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.do_0104, (short)0, lc);
                data.do_0104_length = lc;
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_AES_KEY:
                assertAdmin();
                if((lc != (short)16) && (lc != (short)32)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.aes_key != null) {
                    data.aes_key.clearKey();
                }
                data.aes_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
                                                           (short)(lc * 8),
                                                           false);
                data.aes_key.setKey(buf, (short)0);
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_CARDHOLDER_CERTIFICATE:
                assertAdmin();
                k = currentTagOccurenceToKey();
                if(k == null) {
                    ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                    return;
                }
                k.setCertificate(buf, (short)0, lc);
                break;

            case Constants.TAG_ALGORITHM_ATTRIBUTES_SIG:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].setAttributes(ec, buf, (short)0, lc);
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(data.digital_signature_counter, (short)0,
                                        (byte)data.digital_signature_counter.length, (byte)0);
                JCSystem.commitTransaction();
                break;

            case Constants.TAG_ALGORITHM_ATTRIBUTES_DEC:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].setAttributes(ec, buf, (short)0, lc);
                break;

            case Constants.TAG_ALGORITHM_ATTRIBUTES_AUT:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].setAttributes(ec, buf, (short)0, lc);
                break;

            case Constants.TAG_ALGORITHM_ATTRIBUTES_SM:
                assertAdmin();
                sm.static_key.setAttributes(ec, buf, (short)0, lc);
                break;

            case Constants.TAG_PW_STATUS:
                assertAdmin();
                if(lc != 0x01) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                if((buf[0] != 0x00) && (buf[0] != 0x01)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }
                data.user_pin_force_verify_signature = (buf[0] == 0);
                break;

            case Constants.TAG_FINGERPRINT_SIG:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].fingerprint.set(buf, (short)0, lc);
                break;

            case Constants.TAG_FINGERPRINT_DEC:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].fingerprint.set(buf, (short)0, lc);
                break;

            case Constants.TAG_FINGERPRINT_AUT:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].fingerprint.set(buf, (short)0, lc);
                break;

            case Constants.TAG_FINGERPRINT_CA:
                assertAdmin();
                data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CA].set(buf, (short)0, lc);
                break;

            case Constants.TAG_FINGERPRINT_CB:
                assertAdmin();
                data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CB].set(buf, (short)0, lc);
                break;

            case Constants.TAG_FINGERPRINT_CC:
                assertAdmin();
                data.fingerprints[Persistent.FINGERPRINTS_OFFSET_CC].set(buf, (short)0, lc);
                break;

            case Constants.TAG_GENERATION_DATE_SIG:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].setGenerationDate(buf, (short)0, (short)lc);
                break;

            case Constants.TAG_GENERATION_DATE_DEC:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].setGenerationDate(buf, (short)0, (short)lc);
                break;

            case Constants.TAG_GENERATION_DATE_AUT:
                assertAdmin();
                data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].setGenerationDate(buf, (short)0, (short)lc);
                break;

            case Constants.TAG_RESETTING_CODE:
                assertAdmin();
                if(data.user_puk_is_format_2) {
                    Common.checkPinFormat2(transients.buffer,
                                           (short)0, lc,
                                           Constants.USER_PUK_MIN_SIZE_FORMAT_2,
                                           Constants.USER_PUK_MAX_SIZE_FORMAT_2);
                } else {
                    if((lc < Constants.USER_PUK_MIN_SIZE) ||
                       (lc > Constants.USER_PUK_MAX_SIZE)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                        return;
                    }
                }
                JCSystem.beginTransaction();
                data.user_puk_length = (byte)lc;
                data.user_puk.update(buf, (short)0, data.user_puk_length);
                JCSystem.commitTransaction();
                data.user_puk.resetAndUnblock();
                break;

            case Constants.TAG_KEY_DERIVATION_FUNCTION:
                assertAdmin();
                if((lc < 0) ||
                   (lc > Constants.specialDoMaxLength())) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return;
                }
                JCSystem.beginTransaction();
                if(data.key_derivation_function_length > 0) {
                    Util.arrayFillNonAtomic(data.key_derivation_function, (short)0, data.key_derivation_function_length, (byte)0);
                }
                Util.arrayCopyNonAtomic(buf, (short)0, data.key_derivation_function, (short)0, lc);
                data.key_derivation_function_length = (byte)lc;
                JCSystem.commitTransaction();
                break;

            default:
                ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
                return;
            }
        }
    }

    private final short processGenerateAsymmetricKeyPair(final short lc,
                                                         final byte p1, final byte p2) {

        final byte[] buf = transients.buffer;

        if(((p1 != (byte)0x80) && (p1 != (byte)0x81)) ||
           (p2 != 0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return 0;
        }

        if(lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        boolean do_reset = false;
        PGPKey pkey;

        switch(Util.makeShort(buf[0], buf[1])) {
        case Constants.CRT_SIGNATURE_KEY:
            do_reset = true;
            pkey = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG];
            break;

        case Constants.CRT_DECRYPTION_KEY:
            pkey = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC];
            break;

        case Constants.CRT_AUTHENTICATION_KEY:
            pkey = data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT];
            break;

        case Constants.CRT_SECURE_MESSAGING_KEY:
            pkey = sm.static_key;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return 0;
        }

        if(p1 == (byte)0x80) {

            assertAdmin();

            pkey.generate(ec);

            if(do_reset) {
                JCSystem.beginTransaction();
                Util.arrayFillNonAtomic(data.digital_signature_counter, (short)0,
                                        (byte)data.digital_signature_counter.length, (byte)0);
                JCSystem.commitTransaction();
            }
        }

        return pkey.writePublicKeyDo(buf, (short)0);
    }

    private final short processPerformSecurityOperation(final short lc,
                                                        final byte p1, final byte p2) {

        sensitiveData();

        /* PSO : COMPUTE DIGITAL SIGNATURE */
        if((p1 == (byte)0x9e) && (p2 == (byte)0x9a)) {

            assertUserMode81();

            if(data.user_pin_force_verify_signature) {
                transients.setUserPinMode81(false);
            }

            byte i = 0;
            JCSystem.beginTransaction();
            while(data.digital_signature_counter[(byte)(data.digital_signature_counter.length - i - 1)] == (byte)0xff) {
                ++i;
            }
            if(i < data.digital_signature_counter.length) {
                ++data.digital_signature_counter[(byte)(data.digital_signature_counter.length - i - 1)];
                if(i > 0) {
                    --i;
                    Util.arrayFillNonAtomic(data.digital_signature_counter,
                                            (short)(data.digital_signature_counter.length - i - 1),
                                            (byte)(i + 1), (byte)0);
                }
            }
            JCSystem.commitTransaction();

            return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_SIG].sign(transients.buffer, lc, false);
        }

        /* PSO : DECIPHER */
        if((p1 == (byte)0x80) && (p2 == (byte)0x86)) {

            assertUserMode82();

            if(lc <= 1) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(transients.buffer[0] == (byte)0x02) {

                if(((short)(lc - 1) % Constants.AES_BLOCK_SIZE) != 0) {
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    return 0;
                }

                if((data.aes_key == null) || !data.aes_key.isInitialized()) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }

                cipher_aes_cbc_nopad.init(data.aes_key, Cipher.MODE_DECRYPT);

                final short res = cipher_aes_cbc_nopad.doFinal(transients.buffer, (short)1, (short)(lc - 1),
                                                               transients.buffer, lc);

                Util.arrayCopyNonAtomic(transients.buffer, lc,
                                        transients.buffer, (short)0, res);

                Util.arrayFillNonAtomic(transients.buffer, lc, res, (byte)0);

                return res;
            }

            return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_DEC].decipher(ec, transients.buffer, lc);
        }

        /* PSO : ENCIPHER */
        if((p1 == (byte)0x86) && (p2 == (byte)0x80)) {

            assertUserMode82();

            if((lc <= 0) || ((lc % Constants.AES_BLOCK_SIZE) != 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if((data.aes_key == null) || !data.aes_key.isInitialized()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            cipher_aes_cbc_nopad.init(data.aes_key, Cipher.MODE_ENCRYPT);

            final short res = cipher_aes_cbc_nopad.doFinal(transients.buffer, (short)0, lc,
                                                           transients.buffer, (short)(lc + 1));

            transients.buffer[lc] = (byte)0x02;
            Util.arrayCopyNonAtomic(transients.buffer, lc,
                                    transients.buffer, (short)0, (short)(res + 1));

            Util.arrayFillNonAtomic(transients.buffer, (short)(lc + 1), res, (byte)0);

            return (short)(res + 1);
        }

        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return 0;
    }

    private final short processInternalAuthenticate(final short lc,
                                                    final byte p1, final byte p2) {

        if(p2 == (byte)0x00) {
            switch(p1) {
            case (byte)0x00:
                sensitiveData();
                assertUserMode82();
                return data.pgp_keys[Persistent.PGP_KEYS_OFFSET_AUT].sign(transients.buffer, lc, true);

            case (byte)0x01:
                return sm.establish(transients, ec, transients.buffer, lc);
            }
        }

        ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return 0;
    }

    private final short processGetChallenge(short le,
                                            final byte p1, final byte p2) {
        if((p1 != (byte)0) || (p2 != (byte)0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return 0;
        }

        if(le < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return 0;
        }

        if(le > Constants.challengeMaxLength()) {
            le = Constants.challengeMaxLength();
        }

        if(le != 0) {
            random_data.generateData(transients.buffer, (short)0, le);
        }

        return le;
    }

    private final void processTerminateDf(final byte p1, final byte p2) {

        if((p1 != (byte)0) || (p2 != (byte)0)) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        if(data.admin_pin.getTriesRemaining() <= 0) {
            data.isTerminated = true;
            return;
        }

        assertAdmin();

        data.isTerminated = true;
    }

    private final void processActivateFile(final byte p1, final byte p2) {
        if(p1 != (byte)0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        if(data.isTerminated) {
            switch(p2) {
            case (byte)1:
                sm.reset(false, transients);
                //missing break is intentional

            case (byte)0:
                transients.clear();
                data.reset(false);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
            }
        }
    }

    private final void clearConnection() {
        data.user_pin.reset();
        data.user_puk.reset();
        data.admin_pin.reset();
        transients.clear();
        sm.clearSession(transients);
    }

    public final void process(final APDU apdu) {

        final byte[] apdubuf = apdu.getBuffer();

        if(apdu.isISOInterindustryCLA() && selectingApplet()) {

            clearConnection();

            if(data.isTerminated) {
                ISOException.throwIt(Constants.SW_TERMINATED);
            }

            return;
        }

        transients.setSecureMessagingOk(false);

        if(data.isTerminated) {
            if(apdubuf[ISO7816.OFFSET_CLA] != 0) {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
                return;
            }

            if(apdubuf[ISO7816.OFFSET_INS] == Constants.INS_ACTIVATE_FILE) {
                processActivateFile(apdubuf[ISO7816.OFFSET_P1], apdubuf[ISO7816.OFFSET_P2]);
                return;
            }

            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return;
        }

        final byte p1 = apdubuf[ISO7816.OFFSET_P1];
        final byte p2 = apdubuf[ISO7816.OFFSET_P2];


        short available_le = 0;
        short sw = (short)0x9000;

        if(((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) != Constants.CLA_MASK_CHAINING) &&
           (apdubuf[ISO7816.OFFSET_INS] == Constants.INS_GET_RESPONSE)) {

            if(transients.chainingInput() || !transients.chainingOutput()) {
                ISOException.throwIt(Constants.SW_CHAINING_ERROR);
                return;
            }

            if((p1 != 0) || (p2 != 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
            }

            available_le = transients.outputLength();

        } else if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_CHAINING) == Constants.CLA_MASK_CHAINING) {

            prepareChainingInput(apdubuf);
            receiveData(apdu);

        } else {

            prepareChainingInput(apdubuf);
            receiveData(apdu);

            short lc = transients.chainingInputLength();

            if((apdubuf[ISO7816.OFFSET_CLA] & Constants.CLA_MASK_SECURE_MESSAGING) == Constants.CLA_MASK_SECURE_MESSAGING) {
                short off = lc;

                if((short)(off + 1 + 1 + 1 + 1 + 3) > Constants.INTERNAL_BUFFER_MAX_LENGTH) {
                    ISOException.throwIt(Constants.SW_MEMORY_FAILURE);
                    return;
                }

                transients.buffer[off++] = apdubuf[ISO7816.OFFSET_CLA];
                transients.buffer[off++] = apdubuf[ISO7816.OFFSET_INS];
                transients.buffer[off++] = p1;
                transients.buffer[off++] = p2;
                if(lc > (short)0xff) {
                    transients.buffer[off++] = (byte)0;
                    transients.buffer[off++] = (byte)((lc >> 8) & (byte)0xff);
                }
                transients.buffer[off++] = (byte)(lc & (byte)0xff);

                transients.setChainingInputLength((short)0);

                lc = sm.verifyAndDecryptCommand(transients, lc, off);

                transients.setSecureMessagingOk(true);

            } else if(sm.isSessionAvailable()) {
                clearConnection();
            }

            try {

                switch(apdubuf[ISO7816.OFFSET_INS]) {
                case Constants.INS_SELECT_DATA:
                    processSelectData(lc, p1, p2);
                    break;

                case Constants.INS_GET_DATA:
                    available_le = processGetData(p1, p2);
                    break;

                case Constants.INS_GET_NEXT_DATA:
                    available_le = processGetNextData(p1, p2);
                    break;

                case Constants.INS_VERIFY:
                    processVerify(lc, p1, p2);
                    break;

                case Constants.INS_CHANGE_REFERENCE_DATA:
                    processChangeReferenceData(lc, p1, p2);
                    break;

                case Constants.INS_RESET_RETRY_COUNTER:
                    processResetRetryCounter(lc, p1, p2);
                    break;

                case Constants.INS_PUT_DATA_DA:
                    processPutData(lc, p1, p2, false);
                    break;

                case Constants.INS_PUT_DATA_DB:
                    processPutData(lc, p1, p2, true);
                    break;

                case Constants.INS_GENERATE_ASYMMETRIC_KEY_PAIR:
                    available_le = processGenerateAsymmetricKeyPair(lc, p1, p2);
                    break;

                case Constants.INS_PERFORM_SECURITY_OPERATION:
                    available_le = processPerformSecurityOperation(lc, p1, p2);
                    break;

                case Constants.INS_INTERNAL_AUTHENTICATE:
                    available_le = processInternalAuthenticate(lc, p1, p2);
                    break;

                case Constants.INS_GET_CHALLENGE:
                    available_le = processGetChallenge(apdu.setOutgoing(), p1, p2);
                    break;

                case Constants.INS_TERMINATE_DF:
                    processTerminateDf(p1, p2);
                    break;

                case Constants.INS_ACTIVATE_FILE:
                    processActivateFile(p1, p2);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    return;
                }

            } catch (ISOException e) {
                sw = e.getReason();
            }

            if(transients.secureMessagingOk()) {

                if(available_le > 0) {
                    short tmp = (short)(Constants.AES_BLOCK_SIZE - (available_le % Constants.AES_BLOCK_SIZE));
                    available_le = Util.arrayCopyNonAtomic(SecureMessaging.PADDING_BLOCK, (short)0,
                                                           transients.buffer, available_le,
                                                           tmp);
                }

                if((available_le != 0) ||
                   (sw == (short)0x9000) ||
                   ((short)(sw & (short)0x6200) == (short)0x6200) ||
                   ((short)(sw & (short)0x6300) == (short)0x6300)) {
                    available_le = sm.encryptAndSign(transients, available_le, sw);
                }
            }

            transients.setOutputLength(available_le);
        }



        if(available_le > 0) {

            short resp_le = available_le;

            if(apdu.getCurrentState() != APDU.STATE_OUTGOING) {
                resp_le = apdu.setOutgoing();
                if((resp_le == (short)0) || (available_le < resp_le)) {
                    resp_le = available_le;
                }
            }

            if(resp_le > Constants.APDU_MAX_LENGTH) {
                resp_le = Constants.APDU_MAX_LENGTH;
            }

            short off = transients.outputStart();

            Util.arrayCopyNonAtomic(transients.buffer, off,
                                    apdubuf, (short)0, resp_le);

            apdu.setOutgoingLength(resp_le);
            apdu.sendBytes((short)0, resp_le);

            Util.arrayFillNonAtomic(transients.buffer, off, resp_le, (byte)0);

            available_le -= resp_le;
            off += resp_le;

            if(available_le > 0) {
                transients.setChainingOutput(true);
                transients.setOutputLength(available_le);
                transients.setOutputStart(off);

                if(available_le > (short)0x00ff) {
                    available_le = (short)0x00ff;
                }

                sw = (short)(ISO7816.SW_BYTES_REMAINING_00 | available_le);

            } else {
                transients.setChainingOutput(false);
                transients.setOutputLength((short)0);
                transients.setOutputStart((short)0);
            }
        }

        ISOException.throwIt(sw);
    }
}
