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

public final class Constants {

    protected static final short INTERNAL_BUFFER_MAX_LENGTH =
        (short)((short)0x500);

    protected static final short APDU_MAX_LENGTH = (short)256;

    protected static final byte[] KEY_DERIVATION_FUNCTION_DEFAULT = {
        (byte)0x81, (byte)0x01, (byte)0x00
    };

    protected static final byte USER_PIN_RETRY_COUNT = 3;
    protected static final byte USER_PIN_MIN_SIZE = 0x06;
    protected static final byte USER_PIN_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */
    protected static final byte USER_PIN_MIN_SIZE_FORMAT_2 = 6;
    protected static final byte USER_PIN_MAX_SIZE_FORMAT_2 = 12;
    protected static final byte[] USER_PIN_DEFAULT = {
	(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
	(byte)0x35, (byte)0x36
    };
    protected static final boolean USER_PIN_DEFAULT_IS_FORMAT_2 = false;
    /*
    protected static final byte[] USER_PIN_DEFAULT = {
        (byte)0x26,
        (byte)0x12, (byte)0x34, (byte)0x56, (byte)0xff, (byte)0xff,
        (byte)0xff, (byte)0xff
    };
    protected static final boolean USER_PIN_DEFAULT_IS_FORMAT_2 = true;
    */

    protected static final boolean USER_PIN_DEFAULT_FORCE_VERIFY_SIGNATURE = true;

    protected static final byte USER_PUK_RETRY_COUNT = 3;
    protected static final byte USER_PUK_MIN_SIZE = 0x08;
    protected static final byte USER_PUK_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */
    protected static final byte USER_PUK_MIN_SIZE_FORMAT_2 = 8;
    protected static final byte USER_PUK_MAX_SIZE_FORMAT_2 = 12;

    protected static final byte ADMIN_PIN_RETRY_COUNT = 3;
    protected static final byte ADMIN_PIN_MIN_SIZE = 0x08;
    protected static final byte ADMIN_PIN_MAX_SIZE = 0x7f; /* max is 0x7f because PIN format 2 */
    protected static final byte ADMIN_PIN_MIN_SIZE_FORMAT_2 = 8;
    protected static final byte ADMIN_PIN_MAX_SIZE_FORMAT_2 = 12;
    protected static final byte[] ADMIN_PIN_DEFAULT = {
	(byte)0x31, (byte)0x32, (byte)0x33, (byte)0x34,
	(byte)0x35, (byte)0x36, (byte)0x37, (byte)0x38
    };
    protected static final boolean ADMIN_PIN_DEFAULT_IS_FORMAT_2 = false;
    /*
    protected static final byte[] ADMIN_PIN_DEFAULT = {
        (byte)0x28,
        (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, (byte)0xff,
        (byte)0xff, (byte)0xff
    };
    protected static final boolean ADMIN_PIN_DEFAULT_IS_FORMAT_2 = true;
    */


    protected static final byte FINGERPRINT_SIZE = 20;
    protected static final byte GENERATION_DATE_SIZE = 4;

    protected static final byte NAME_MAX_LENGTH = 39;
    protected static final byte LANG_MIN_LENGTH = 2;
    protected static final byte LANG_MAX_LENGTH = 8;
    protected static final byte[] LANG_DEFAULT = { (byte)0x65, (byte)0x6e };

    protected static final byte SEX_MALE = (byte)0x31;
    protected static final byte SEX_FEMALE = (byte)0x32;
    protected static final byte SEX_NOT_ANNOUNCED = (byte)0x39;

    protected static final short TAG_AID = (short)0x004f;
    protected static final short TAG_LOGIN = (short)0x005e;
    protected static final short TAG_URL = (short)0x5f50;
    protected static final short TAG_HISTORICAL_BYTES_CARD_SERVICE_CARD_CAPABILITIES = (short)0x5f52;
    protected static final short TAG_CARDHOLDER_RELATED_DATA = (short)0x0065;
    protected static final short TAG_APPLICATION_RELATED_DATA = (short)0x006e;
    protected static final short TAG_SECURITY_SUPPORT_TEMPLATE = (short)0x007a;
    protected static final short TAG_CARDHOLDER_CERTIFICATE = (short)0x7f21;
    protected static final short TAG_NAME = (short)0x005b;
    protected static final short TAG_LANG = (short)0x5f2d;
    protected static final short TAG_SEX = (short)0x5f35;
    protected static final short TAG_ALGORITHM_ATTRIBUTES_SIG = (short)0x00c1;
    protected static final short TAG_ALGORITHM_ATTRIBUTES_DEC = (short)0x00c2;
    protected static final short TAG_ALGORITHM_ATTRIBUTES_AUT = (short)0x00c3;
    protected static final short TAG_ALGORITHM_ATTRIBUTES_SM = (short)0x00d4;
    protected static final short TAG_PW_STATUS = (short)0x00c4;
    protected static final short TAG_KEY_FINGERPRINTS = (short)0x00c5;
    protected static final short TAG_CA_FINGERPRINTS = (short)0x00c6;
    protected static final short TAG_FINGERPRINT_SIG = (short)0x00c7;
    protected static final short TAG_FINGERPRINT_DEC = (short)0x00c8;
    protected static final short TAG_FINGERPRINT_AUT = (short)0x00c9;
    protected static final short TAG_FINGERPRINT_CA = (short)0x00ca;
    protected static final short TAG_FINGERPRINT_CB = (short)0x00cb;
    protected static final short TAG_FINGERPRINT_CC = (short)0x00cc;
    protected static final short TAG_KEY_GENERATION_DATES = (short)0x00cd;
    protected static final short TAG_GENERATION_DATE_SIG = (short)0x00ce;
    protected static final short TAG_GENERATION_DATE_DEC = (short)0x00cf;
    protected static final short TAG_GENERATION_DATE_AUT = (short)0x00d0;
    protected static final short TAG_RESETTING_CODE = (short)0x00d3;
    protected static final short TAG_EXTENDED_LENGTH_INFORMATION = (short)0x7f66;
    protected static final short TAG_PRIVATE_DO_0101 = (short)0x0101;
    protected static final short TAG_PRIVATE_DO_0102 = (short)0x0102;
    protected static final short TAG_PRIVATE_DO_0103 = (short)0x0103;
    protected static final short TAG_PRIVATE_DO_0104 = (short)0x0104;
    protected static final short TAG_AES_KEY = (short)0x00d5;
    protected static final short TAG_KEY_DERIVATION_FUNCTION = (short)0x00f9;

    protected static final short CRT_AUTHENTICATION_KEY = (short)0xa400;
    protected static final short CRT_SECURE_MESSAGING_KEY = (short)0xa600;
    protected static final short CRT_SIGNATURE_KEY = (short)0xb600;
    protected static final short CRT_DECRYPTION_KEY = (short)0xb800;

    protected static final byte CLA_MASK_CHAINING = (byte)0x10;
    protected static final byte CLA_MASK_SECURE_MESSAGING = (byte)0x04;


    protected static final byte INS_SELECT_DATA = (byte)0xA5;
    protected static final byte INS_GET_DATA = (byte)0xCA;
    protected static final byte INS_GET_NEXT_DATA = (byte)0xCC;
    protected static final byte INS_VERIFY = (byte)0x20;
    protected static final byte INS_CHANGE_REFERENCE_DATA = (byte)0x24;
    protected static final byte INS_RESET_RETRY_COUNTER = (byte)0x2C;
    protected static final byte INS_PUT_DATA_DA = (byte)0xDA;
    protected static final byte INS_PUT_DATA_DB = (byte)0xDB;
    protected static final byte INS_GENERATE_ASYMMETRIC_KEY_PAIR = (byte)0x47;
    protected static final byte INS_PERFORM_SECURITY_OPERATION = (byte)0x2A;
    protected static final byte INS_INTERNAL_AUTHENTICATE = (byte)0x88;
    protected static final byte INS_GET_RESPONSE = (byte)0xC0;
    protected static final byte INS_GET_CHALLENGE = (byte)0x84;
    protected static final byte INS_TERMINATE_DF = (byte)0xE6;
    protected static final byte INS_ACTIVATE_FILE = (byte)0x44;


    protected static final short SW_TERMINATED = (short)0x6285;
    protected static final short SW_MEMORY_FAILURE = (short)0x6581;
    protected static final short SW_CHAINING_ERROR = (short)0x6883;
    protected static final short SW_REFERENCE_DATA_NOT_FOUND = (short)0x6A88;



    protected static final byte[] HISTORICAL_BYTES = {
        (byte)0x00, /* category indicator byte */

        (byte)0xC1, /* card service data */
        (byte)0xC5, /* ... */

        (byte)0x73, /* card capabilities */
        (byte)0xC0, /* 1st byte: "methods supported" see ISO 7816-4 */
        (byte)0x01, /* 2nd byte: "data coding byte" idem */
        (byte)0x80, /* 3rd byte: command chaining (not extended length by default as all readers do not support them...) */

        (byte)0x05, /* status indicator byte : operational state */
        (byte)0x90, /* SW1 */
        (byte)0x00  /* SW2 */
    };

    protected static final byte[] EXTENDED_CAPABILITIES = {
        (byte)(0x80 | /* support secure messaging */
               0x40 | /* support get challenge */
               0x20 | /* support key import */
               0x10 | /* support pw status changes */
               0x08 | /* support private DOs (0101-0104) */
               0x04 | /* support algorithm attributes changes */
               0x02 | /* support PSO:DEC/ENC AES */
               0x01), /* support KDF-DO */
        (byte)0x03, /* SM 0x01 = 128 bits, 0x02 = 256 bits, 0x03 = SCP11b */
        (byte)0x00, (byte)0x20, /* max length get challenge */
        (byte)0x04, (byte)0x80, /* max length of carholder certificate */
        (byte)0x00, (byte)0xff, /* max length of special DOs (private, login, url, KDF-DO) */
        (byte)0x01, /* PIN format 2 is supported */
        (byte)0x00  /* MSE not supported */
    };

    protected static final short challengeMaxLength() {
        return Util.getShort(EXTENDED_CAPABILITIES, (short)2);
    }

    protected static final short cardholderCertificateMaxLength() {
        return Util.getShort(EXTENDED_CAPABILITIES, (short)4);
    }

    protected static final short specialDoMaxLength() {
        return Util.getShort(EXTENDED_CAPABILITIES, (short)6);
    }


    protected static final byte[] DSI_SHA224_HEADER = {
        (byte)0x30, (byte)0x2D,
        (byte)0x30, (byte)0x0D,
        (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x04,
        (byte)0x05, (byte)0x00,
        (byte)0x04, (byte)0x1C
    };

    protected static final byte[] DSI_SHA256_HEADER = {
        (byte)0x30, (byte)0x31,
        (byte)0x30, (byte)0x0D,
        (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
        (byte)0x05, (byte)0x00,
        (byte)0x04, (byte)0x20
    };

    protected static final byte[] DSI_SHA384_HEADER = {
        (byte)0x30, (byte)0x41,
        (byte)0x30, (byte)0x0D,
        (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x02,
        (byte)0x05, (byte)0x00,
        (byte)0x04, (byte)0x30
    };

    protected static final byte[] DSI_SHA512_HEADER = {
        (byte)0x30, (byte)0x51,
        (byte)0x30, (byte)0x0D,
        (byte)0x06, (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x03,
        (byte)0x05, (byte)0x00,
        (byte)0x04, (byte)0x40
    };


    protected static final byte ALGORITHM_ATTRIBUTES_MIN_LENGTH = 6;
    protected static final byte ALGORITHM_ATTRIBUTES_MAX_LENGTH = 13;

    protected static final byte[] ALGORITHM_ATTRIBUTES_DEFAULT = {
        (byte)0x01, /* RSA */
        (byte)0x08, (byte)0x00, /* 2048 bits modulus */
        (byte)0x00, (byte)0x11, /* 65537 = 17 bits public exponent */
        (byte)0x03 /* crt form with modulus */
    };

    protected static final byte[] ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING = {
        (byte)0x12, /* ECDH */
        (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, /* ansix9p256r1 */
        (byte)0xFF /* with public key */
    };

    protected static final byte[] RSA_EXPONENT = { (byte)0x01, (byte)0x00, (byte)0x01 };

    protected static final short AES_BLOCK_SIZE = (short)16;

}
