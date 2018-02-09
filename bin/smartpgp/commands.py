#!/usr/bin/env python

# SmartPGP : JavaCard implementation of OpenPGP card v3 specification
# https://github.com/ANSSI-FR/SmartPGP
# Copyright (C) 2016 ANSSI

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString

import struct

SELECT = [0x00, 0xA4, 0x04, 0x00,
          0x06,
          0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
          0x00]

VERIFY_ADMIN = [0x00, 0x20, 0x00, 0x83]
VERIFY_USER_82 = [0x00, 0x20, 0x00, 0x82]
TERMINATE = [0x00, 0xe6, 0x00, 0x00]
ACTIVATE = [0x00, 0x44, 0x00, 0x00]
ACTIVATE_FULL = [0x00, 0x44, 0x00, 0x01]
GET_SM_CURVE_OID = [0x00, 0xca, 0x00, 0xd4]
GENERATE_ASYMETRIC_KEYPAIR = [0x00, 0x47, 0x80, 0x00]

ALGS_ALIASES = {
    'ansix9p256r1': 'ansix9p256r1',
    'P256': 'ansix9p256r1',
    'P-256': 'ansix9p256r1',
    'NIST-P256': 'ansix9p256r1',
    'ansix9p384r1': 'ansix9p384r1',
    'P384': 'ansix9p384r1',
    'P-384': 'ansix9p384r1',
    'NIST-P384': 'ansix9p384r1',
    'ansix9p521r1': 'ansix9p521r1',
    'P521': 'ansix9p521r1',
    'P-521': 'ansix9p521r1',
    'NIST-P521': 'ansix9p521r1',

    'brainpoolP256r1': 'brainpoolP256r1',
    'BP256': 'brainpoolP256r1',
    'BP-256': 'brainpoolP256r1',
    'brainpool256': 'brainpoolP256r1',
    'brainpoolP384r1': 'brainpoolP384r1',
    'BP384': 'brainpoolP384r1',
    'BP-384': 'brainpoolP384r1',
    'brainpool384': 'brainpoolP384r1',
    'brainpoolP512r1': 'brainpoolP512r1',
    'BP512': 'brainpoolP512r1',
    'BP-512': 'brainpoolP512r1',
    'brainpool512': 'brainpoolP512r1',
}

OID_ALGS = {
    'ansix9p256r1': [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    'ansix9p384r1': [0x2B, 0x81, 0x04, 0x00, 0x22],
    'ansix9p521r1': [0x2B, 0x81, 0x04, 0x00, 0x23],
    'brainpoolP256r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    'brainpoolP384r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    'brainpoolP512r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
}

class WrongKeyRole(Exception):
    pass

class WrongAlgo(Exception):
    pass

def ascii_encode_pin(pin):
    return [ord(c) for c in pin]

def assemble_with_len(prefix,data):
    return prefix + [len(data)] + data

def asOctets(bs):
    l = len(bs)
    if l%8 is not 0:
        raise "BitString length is not a multiple of 8"
    result = []
    i = 0
    while i < l:
        byte = 0
        for x in range(8):
            byte |= bs[i + x] << (7 - x)
        result.append(byte)
        i += 8
    return result

def encode_len(data):
    l = len(data)
    if l > 0xff:
        l = [0x82, (l >> 8) & 0xff, l & 0xff]
    elif l > 0x7f:
        l = [0x81, l & 0xff]
    else:
        l = [l & 0xff]
    return l

def _raw_send_apdu(connection, text, apdu):
    print "%s" % text
    apdu = [int(c) for c in apdu]
    #print ' '.join('{:02X}'.format(c) for c in apdu)
    (data, sw1, sw2) = connection.transmit(apdu)
    #print ' '.join('{:02X}'.format(c) for c in data)
    print "%02X %02X" % (sw1, sw2)
    return (data,sw1,sw2)

def list_readers():
    for reader in readers():
        try:
            connection = reader.createConnection()
            connection.connect()
            print(reader, toHexString(connection.getATR()))
        except NoCardException:
            print(reader, 'no card inserted')

def select_reader(reader_index):
    reader_list = readers()
    r = reader_list[reader_index]
    conn = r.createConnection()
    conn.connect()
    return conn

def select_applet(connection):
    return _raw_send_apdu(connection,"Select OpenPGP Applet",SELECT)

def verif_admin_pin(connection, admin_pin):
    verif_apdu = assemble_with_len(VERIFY_ADMIN,ascii_encode_pin(admin_pin))
    return _raw_send_apdu(connection,"Verify Admin PIN",verif_apdu)

def verif_user_pin(connection, user_pin):
    verif_apdu = assemble_with_len(VERIFY_USER_82,ascii_encode_pin(user_pin))
    return _raw_send_apdu(connection,"Verify User PIN",verif_apdu)

def full_reset_card(connection):
    _raw_send_apdu(connection,"Terminate",TERMINATE)
    _raw_send_apdu(connection,"Activate",ACTIVATE_FULL)

def reset_card(connection):
    _raw_send_apdu(connection,"Terminate",TERMINATE)
    _raw_send_apdu(connection,"Activate",ACTIVATE)

def switch_crypto_rsa(connection,key_role):
    data = [
        0x01,       # RSA
        0x08, 0x00, # 2048 bits modulus
        0x00, 0x11, # 65537 - 17 bits public exponent
        0x03]       # crt form with modulus
    if key_role == 'sig':
        role = 0xc1
    elif key_role == 'dec':
        role = 0xc2
    elif key_role == 'auth':
        role = 0xc3
    elif key_role == 'sm':
        role = 0xd4
    else:
        raise WrongKeyRole
    prefix = [0x00, 0xDA, 0x00] + [role]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Switch to RSA2048 (%s)" % (key_role,),apdu)

def switch_crypto(connection,crypto,key_role):
    alg_name = None
    role = None
    # treat RSA differently
    if crypto=='rsa2048' or crypto=='RSA2048' or crypto=='rsa' or crypto=='RSA':
        return switch_crypto_rsa(connection,key_role)
    # this code is only for elliptic curves
    try:
        alg_name = ALGS_ALIASES[crypto]
    except KeyError:
        raise WrongAlgo
    data = OID_ALGS[alg_name]
    byte1 = 0x12
    if key_role == 'sig':
        role = 0xc1
        byte1 = 0x13
    elif key_role == 'dec':
        role = 0xc2
    elif key_role == 'auth':
        role = 0xc3
    elif key_role == 'sm':
        role = 0xd4
    else:
        raise WrongKeyRole
    prefix = [0x00, 0xDA, 0x00] + [role]
    apdu = assemble_with_len(prefix, [byte1] + data + [0xff])
    _raw_send_apdu(connection,"Switch to %s (%s)" % (crypto,key_role),apdu)

def generate_sm_key(connection):
    apdu = assemble_with_len(GENERATE_ASYMETRIC_KEYPAIR, [0xA6, 0x00])
    apdu = apdu + [0x00]
    return _raw_send_apdu(connection,"Generate SM key",apdu)

def set_resetting_code(connection, resetting_code): 
    apdu = assemble_with_len([0x00, 0xDA, 0x00, 0xD3], ascii_encode_pin(resetting_code))
    _raw_send_apdu(connection,"Define the resetting code (PUK)",apdu)

def unblock_pin(connection, resetting_code, new_user_pin):
    data = ascii_encode_pin(resetting_code)+ascii_encode_pin(new_user_pin)
    apdu = assemble_with_len([0x00, 0x2C, 0x00, 0x81], data)
    _raw_send_apdu(connection,"Unblock user PIN with resetting code",apdu)

def put_sm_key(connection, pubkey, privkey):
    ins_p1_p2 = [0xDB, 0x3F, 0xFF]
    cdata = [0x92] + encode_len(privkey) + [0x99] + encode_len(pubkey)
    cdata = [0xA6, 0x00, 0x7F, 0x48] + encode_len(cdata) + cdata
    cdata = cdata + [0x5F, 0x48] + encode_len(privkey + pubkey) + privkey + pubkey
    cdata = [0x4D] + encode_len(cdata) + cdata
    i = 0
    cl = 255
    l = len(cdata)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = cdata[i:]
            i = l
        else:
            cla = 0x10
            data = cdata[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        _raw_send_apdu(connection,"Sending SM key chunk",apdu)

def put_sm_certificate(connection, cert):
    prefix = [0x00, 0xA5, 0x03, 0x04]
    data = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Selecting SM certificate",apdu)
    ins_p1_p2 = [0xDA, 0x7F, 0x21]
    i = 0
    cl = 255
    l = len(cert)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = cert[i:]
            i = l
        else:
            cla = 0x10
            data = cert[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        _raw_send_apdu(connection,"Sending SM certificate chunk",apdu)

def get_sm_certificate(connection):
    prefix = [0x00, 0xA5, 0x03, 0x04]
    data = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Selecting SM certificate",apdu)
    apdu = [0x00, 0xCA, 0x7F, 0x21, 0x00]
    (data,sw1,sw2) = _raw_send_apdu(connection,"Receiving SM certificate chunk",apdu)
    while sw1 == 0x61:
        apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
        (ndata,sw1,sw2) = _raw_send_apdu(connection,"Receiving SM certificate chunk",apdu)
        data = data + ndata
    return (data,sw1,sw2)

def get_sm_curve_oid(connection):
    """ Get Curve OID for Secure Messaging
        Return Curve OID (DER-encoded)
    """
    apdu = GET_SM_CURVE_OID + [0x00]
    (data,sw1,sw2) = _raw_send_apdu(connection,"SM Curve OID",apdu)
    b = bytearray(data)
    assert(b[0]==0xd4)
    curve_len = b[1]
    curve = b[2:]
    assert(curve_len == len(curve))
    assert(curve[0])==0x12
    curve = curve[1:]
    if curve[-1] == 0xff:
        curve.pop()
    #print ' '.join('{:02X}'.format(c) for c in curve)
    # Add DER OID header manually ...
    return '\x06' + struct.pack('B',len(curve)) + curve

def put_aes_key(connection, key):
    prefix = [0x00, 0xDA, 0x00, 0xD5]
    data = key
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Put AES key",apdu)

def encrypt_aes(connection, msg):
    ins_p1_p2 = [0x2A, 0x86, 0x80]
    i = 0
    cl = 255
    l = len(msg)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = msg[i:]
            i = l
        else:
            cla = 0x10
            data = msg[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        (res,sw1,sw2) = _raw_send_apdu(connection,"Encrypt AES chunk",apdu)
        while sw1 == 0x61:
            apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
            (nres,sw1,sw2) = _raw_send_apdu(connection,"Receiving encrypted chunk",apdu)
            res = res + nres
    return (res[1:],sw1,sw2)


def decrypt_aes(connection, msg):
    ins_p1_p2 = [0x2A, 0x80, 0x86]
    i = 0
    cl = 255
    msg = [0x02] + msg
    l = len(msg)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = msg[i:]
            i = l
        else:
            cla = 0x10
            data = msg[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        (res,sw1,sw2) = _raw_send_apdu(connection,"Decrypt AES chunk",apdu)
        while sw1 == 0x61:
            apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
            (nres,sw1,sw2) = _raw_send_apdu(connection,"Receiving decrypted chunk",apdu)
            res = res + nres
    return (res,sw1,sw2)


def put_kdf_do(connection, kdf_do):
    prefix = [0x00, 0xDA, 0x00, 0xF9]
    data = kdf_do
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Put KDF-DO",apdu)
