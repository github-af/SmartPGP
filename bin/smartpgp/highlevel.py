
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

from commands import *

import binascii
import pyasn1
from pyasn1.type import univ
from pyasn1.codec.der import encoder as der_encoder,decoder as der_decoder



class InvalidKDF(Exception):
    pass

class ConnectionFailed(Exception):
    pass

class AdminPINFailed(Exception):
    pass

class UserPINFailed(Exception):
    pass

class CardConnectionContext:

    def __init__(self):
        self.reader_index = 0
        self.admin_pin = "123456"
        self.admin_pin = "12345678"
        self.connection = None
        self.read_pin = self._default_pin_read_function
        self.connected = False
        self.verified = False
        self.input = None

    def _default_pin_read_function(self, pin_type):
        return self.admin_pin

    def set_pin_read_function(self, fun):
        self.read_pin = fun

    def verify_admin_pin(self):
        if self.verified:
            return
        admin_pin = self.read_pin("Admin")
        (_,sw1,sw2)=verif_admin_pin(self.connection, admin_pin)
        if sw1==0x90 and sw2==0x00:
            self.verified = True
        else:
            raise AdminPINFailed

    def verify_user_pin(self):
        if self.verified:
            return
        user_pin = self.read_pin("User")
        (_,sw1,sw2)=verif_user_pin(self.connection, user_pin)
        if sw1==0x90 and sw2==0x00:
            self.verified = True
        else:
            raise UserPINFailed
        
    def connect(self):
        if self.connected:
            return
        self.connection = select_reader(self.reader_index)
        (_,sw1,sw2)=select_applet(self.connection)
        if sw1==0x90 and sw2==0x00:
            self.connected = True
        else:
            raise ConnectionFailed

    def cmd_list_readers(self):
        list_readers()

    def cmd_full_reset(self):
        # ignore errors
        self.connection = select_reader(self.reader_index)
        select_applet(self.connection)
        # do not use self.verify_admin_pin(), we want to force sending the APDUs
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        full_reset_card(self.connection)
        # force re-entering admin PIN
        self.verified = False

    def cmd_reset(self):
        # ignore errors
        self.connection = select_reader(self.reader_index)
        select_applet(self.connection)
        # do not use self.verify_admin_pin(), we want to force sending the APDUs
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        reset_card(self.connection)
        # force re-entering admin PIN
        self.verified = False

    def cmd_switch_crypto(self,alg_name,key_role):
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection,alg_name,key_role)

    def cmd_switch_all_crypto(self,alg_name):
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection,alg_name,'sig')
        switch_crypto(self.connection,alg_name,'dec')
        switch_crypto(self.connection,alg_name,'auth')

    def cmd_switch_bp256(self):
        self.cmd_switch_all_crypto('brainpoolP256r1')

    def cmd_switch_bp384(self):
        self.cmd_switch_all_crypto('brainpoolP384r1')

    def cmd_switch_bp512(self):
        self.cmd_switch_all_crypto('brainpoolP512r1')

    def cmd_switch_p256(self):
        self.cmd_switch_all_crypto('P-256')

    def cmd_switch_p384(self):
        self.cmd_switch_all_crypto('P-384')

    def cmd_switch_p521(self):
        self.cmd_switch_all_crypto('P-521')

    def cmd_switch_rsa2048(self):
        self.cmd_switch_all_crypto('rsa2048')

    def cmd_generate_sm_key(self):
        if not self.output:
            print "Missing output file name"
            return
        self.connect()
        self.verify_admin_pin()
        (data,sw1,sw2) = generate_sm_key(self.connection)
        if sw1!=0x90 or sw2!=0x00:
            print "generate_sm_key failed"
            return
        if len(data) < 4 or data[0]!=0x7f or data[1]!=0x49:
            print "Strange reply for get_sm_certificate"
            return
        blob_len = data[2]
        blob = data[3:]
        assert(blob_len == len(blob))
        if blob[0]!=0x86:
            print "get_sm_certificate return something not a public key"
            return
        assert(blob[1]==len(blob[2:]))
        pubkey = blob[2:]
        # get curve OID
        curve_oid_der = get_sm_curve_oid(self.connection)
        if not curve_oid_der:
            print "Error getting SM curve OID"
            return
        (curve_oid,_) = der_decoder.decode(str(curve_oid_der))
        # now format it to DER [RFC5480]
        s = univ.Sequence()
        oid_elliptic_curve_pubkey = univ.ObjectIdentifier('1.2.840.10045.2.1')
        s.setComponentByPosition(0,oid_elliptic_curve_pubkey)
        s.setComponentByPosition(1,curve_oid)
        bs = univ.BitString("'%s'H" % binascii.hexlify(bytearray(pubkey)))
        s2 = univ.Sequence()
        s2.setComponentByPosition(0,s)
        s2.setComponentByPosition(1,bs)
        pubkey_der = der_encoder.encode(s2)
        print binascii.hexlify(pubkey_der)
        # and write result
        with open(self.output,"wb") as f:
            f.write(pubkey_der)
            f.close()

    def cmd_get_sm_key(self):
        if not self.output:
            print "Missing output file name"
            return
        self.connect()
        (data,sw1,sw2) = get_sm_key(self.connection)
        if sw1!=0x90 or sw2!=0x00:
            print "get_sm_key failed"
            return
        if len(data) < 4 or data[0]!=0x7f or data[1]!=0x49:
            print "Strange reply for get_sm_key"
            return
        blob_len = data[2]
        blob = data[3:]
        assert(blob_len == len(blob))
        if blob[0]!=0x86:
            print "get_sm_key something not a public key"
            return
        assert(blob[1]==len(blob[2:]))
        pubkey = blob[2:]
        # get curve OID
        curve_oid_der = get_sm_curve_oid(self.connection)
        if not curve_oid_der:
            print "Error getting SM curve OID"
            return
        (curve_oid,_) = der_decoder.decode(str(curve_oid_der))
        # now format it to DER [RFC5480]
        s = univ.Sequence()
        oid_elliptic_curve_pubkey = univ.ObjectIdentifier('1.2.840.10045.2.1')
        s.setComponentByPosition(0,oid_elliptic_curve_pubkey)
        s.setComponentByPosition(1,curve_oid)
        bs = univ.BitString("'%s'H" % binascii.hexlify(bytearray(pubkey)))
        s2 = univ.Sequence()
        s2.setComponentByPosition(0,s)
        s2.setComponentByPosition(1,bs)
        pubkey_der = der_encoder.encode(s2)
        print binascii.hexlify(pubkey_der)
        # and write result
        with open(self.output,"wb") as f:
            f.write(pubkey_der)
            f.close()

    def cmd_put_sm_key(self):
        if self.input is None:
            print "No input key file"
            return
        f = open(self.input, 'r')
        fstr = f.read()
        f.close()
        (der,_) = der_decoder.decode(fstr)
        privkey = [ord(c) for c in der[1].asOctets()]
        oid = bytearray(der_encoder.encode(der[2]))
        pubkey = asOctets(der[3])
        if oid[0] == 0xa0:
            oid = oid[2:]
        oid_len = oid[1]
        oid = oid[2:]
        assert(oid_len == len(oid))
        curve = None
        for k,v in OID_ALGS.items():
            if bytearray(v) == oid:
                curve = k
        if curve is None:
            print "Curve not supported (%s)" % der[2]
            return
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection, curve, 'sm')
        put_sm_key(self.connection, pubkey, privkey)

    def cmd_set_resetting_code(self):
        self.connect()
        self.verify_admin_pin()
        resetting_code = self.read_pin("PUK")
        set_resetting_code(self.connection, resetting_code)

    def cmd_unblock_pin(self):
        self.connect()
        resetting_code = self.read_pin("PUK")
        new_user_pin = self.read_pin("new user")
        unblock_pin(self.connection, resetting_code, new_user_pin)

    def cmd_put_sign_certificate(self):
        if self.input is None:
            print "No input certificate file"
            return
        f = open(self.input, 'r')
        cert = f.read()
        cert = [ord(c) for c in cert]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_sign_certificate(self.connection, cert)

    def cmd_put_auth_certificate(self):
        if self.input is None:
            print "No input certificate file"
            return
        f = open(self.input, 'r')
        cert = f.read()
        cert = [ord(c) for c in cert]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_auth_certificate(self.connection, cert)

    def cmd_put_sm_certificate(self):
        if self.input is None:
            print "No input certificate file"
            return
        f = open(self.input, 'r')
        cert = f.read()
        cert = [ord(c) for c in cert]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_sm_certificate(self.connection, cert)

    def cmd_get_sm_certificate(self):
        if self.output is None:
            print "No output file"
            return
        self.connect()
        (cert,_,_) = get_sm_certificate(self.connection)
        cert = "".join([chr(c) for c in cert])
        with open(self.output, 'w') as f:
            f.write(cert)
            f.close()

    def cmd_put_aes_key(self):
        if self.input is None:
            print "No input AES key file"
            return
        f = open(self.input, 'r')
        key = f.read()
        key = [ord(c) for c in key]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_aes_key(self.connection, key)

    def cmd_encrypt_aes(self):
        if self.input is None:
            print "No input data file"
            return
        if self.output is None:
            print "No output data file"
            return
        f = open(self.input, 'r')
        data = f.read()
        data = [ord(c) for c in data]
        f.close()
        self.connect()
        self.verify_user_pin()
        (data,_,_) = encrypt_aes(self.connection, data)
        data = "".join([chr(c) for c in data])
        with open(self.output, 'w') as f:
            f.write(data)
            f.close()
 
    def cmd_decrypt_aes(self):
        if self.input is None:
            print "No input data file"
            return
        if self.output is None:
            print "No output data file"
            return
        f = open(self.input, 'r')
        data = f.read()
        data = [ord(c) for c in data]
        f.close()
        self.connect()
        self.verify_user_pin()
        (data,_,_) = decrypt_aes(self.connection, data)
        data = "".join([chr(c) for c in data])
        with open(self.output, 'w') as f:
            f.write(data)
            f.close()

    def cmd_set_kdf(self):
        if self.input is None:
            print "No input KDF-DO"
            return
        f = open(self.input, 'r')
        kdf_do = f.read()
        kdf_do = [ord(c) for c in kdf_do]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_kdf_do(self.connection, kdf_do)

    def cmd_get_kdf(self):
        if self.output is None:
            print "No output file"
            return
        self.connect()
        (kdf_do,_,_) = get_kdf_do(self.connection)
        kdf_do = "".join([chr(c) for c in kdf_do])
        with open(self.output, 'w') as f:
            f.write(kdf_do)
            f.close()


    def cmd_setup_kdf(self):
        self.connect()
        (kdf_do,_,_) = get_kdf_do(self.connection)
        if 5 < len(kdf_do):
            print "KDF already setup"
            return
        ####### step 1
        pw1 = self.read_pin("User")
        resetting_code = self.read_pin("PUK")
        if len(resetting_code) == 0:
            resetting_code = None
        pw3 = self.read_pin("Admin")
        ####### step 1bis
        pw1 = pw1
        if resetting_code <> None:
            resetting_code = resetting_code
        pw3 = pw3
        ####### step 2
        salt_size = 8
        algo = 0x08 #SHA256
        nbiter = 200000
        ndata81 = [0x81, 0x01, 0x03] #KDF_ITERSALTED_S2K
        ndata82 = [0x82, 0x01, algo]
        ndata83 = [0x83, 0x04, nbiter >> 24, (nbiter >> 16) & 0xff, (nbiter >> 8) & 0xff, nbiter & 0xff] #NB ITERATIONS
        salt_pw1 = os.urandom(salt_size)
        ndata84 = assemble_with_len([0x84], [ord(c) for c in salt_pw1]) #SALT PW1
        salt_resetting_code = os.urandom(salt_size)
        ndata85 = assemble_with_len([0x85], [ord(c) for c in salt_resetting_code]) #SALT RESETTING CODE
        salt_pw3 = os.urandom(salt_size)
        ndata86 = assemble_with_len([0x86], [ord(c) for c in salt_pw3]) #SALT PW3
        h87 = kdf_itersalted_s2k(salt_pw1, "123456", algo, nbiter) #HASH OF "123456"
        h87 = [ord(c) for c in h87]
        ndata87 = assemble_with_len([0x87], h87)
        h88 = kdf_itersalted_s2k(salt_pw3, "12345678", algo, nbiter) #HASH OF "12345678"
        h88 = [ord(c) for c in h88]
        ndata88 = assemble_with_len([0x88], h88)
        nkdf_do = ndata81 + ndata82 + ndata83 + ndata84 + ndata85 + ndata86 + ndata87 + ndata88
        ####### step 2bis
        npw1 = kdf_itersalted_s2k(salt_pw1, pw1, algo, nbiter)
        if resetting_code <> None:
            nresetting_code = kdf_itersalted_s2k(salt_resetting_code, resetting_code, algo, nbiter)
        else:
            nresetting_code = None
        npw3 = kdf_itersalted_s2k(salt_pw3, pw3, algo, nbiter)
        ####### step 3
        (_,sw1,sw2) = verif_admin_pin(self.connection, pw3)
        if sw1==0x90 and sw2==0x00:
            self.verified = True
        else:
            raise AdminPINFailed
        ####### step 3bis
        if nresetting_code <> None:
            set_resetting_code(self.connection, nresetting_code)
            if sw1!=0x90 or sw2!=0x00:
                print "set_resetting_code failed"
                return
        ####### step 4
        change_reference_data_pw1(self.connection, pw1, npw1)
        if sw1!=0x90 or sw2!=0x00:
            print "change_reference_data_pw1 failed"
            return
        ####### step 4bis
        change_reference_data_pw3(self.connection, pw3, npw3)
        if sw1!=0x90 or sw2!=0x00:
            print "change_reference_data_pw3 failed"
            return
        ####### step 5
        put_kdf_do(self.connection, nkdf_do)
