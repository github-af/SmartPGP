#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Testing SmartPGP applet up to a crash because of a memory leak

import os
from sys import path
import subprocess
import getpass
import hashlib
import tempfile


path.append(".")
import OpenPGPpy


def sha256(data):
    return hashlib.sha256(data).digest()


def pubkey_to_der(pubkey):
    # Add ASN1 DER header (EC parameters)
    # ECP 256 r1 header
    header_hex = "3059301306072A8648CE3D020106082A8648CE3D030107034200"
    return bytes.fromhex(header_hex + pubkey.hex())


def check_signature(msg, signature, pubkeyd):
    pubkey = pubkey_to_der(pubkeyd)
    fpk = tempfile.NamedTemporaryFile(delete=False)
    fpk.write(pubkey)
    fpk.close()
    fsig = tempfile.NamedTemporaryFile(delete=False)
    fsig.write(signature)
    fsig.close()
    verify_cmd = (
        f"openssl dgst -sha256 -keyform DER -verify {fpk.name} -signature {fsig.name}"
    )
    sigOK = False
    try:
        subprocess.run(
            verify_cmd, input=msg, shell=True, check=True, stdout=subprocess.PIPE
        )
        sigOK = True
    except Exception:
        print("Error in signature verification")
        print(">>> Requires openssl in path to check signatures")
        sigOK = False
    os.remove(fpk.name)
    os.remove(fsig.name)
    return sigOK


def main():
    try:
        # instanciated with (True) to enable debug mode
        mydevice = OpenPGPpy.OpenPGPcard(True)
    except OpenPGPpy.ConnectionException as exc:
        print(exc)
        return
    print("OpenPGP device detected")
    pubkey_card_all = None
    try:
        pubkey_card_all = mydevice.get_public_key("B600")
    except OpenPGPpy.PGPCardException as exc:
        # SW = 0x6581 or 0x6A88 ?
        if exc.sw_code != 0x6581 and exc.sw_code != 0x6A88:
            raise
        # SIGn key was not created, continue to setup this key
    if pubkey_card_all is None:
        print("Setup the new device")
        PIN3 = "12345678" #getpass.getpass("Enter PIN3 (PUK) : ")
        try:
            mydevice.verify_pin(3, PIN3)
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw_code == 0x6982 or exc.sw_code == 0x6A80:
                print("Error: Wrong PUK")
            return
        # Setup EC256r1 for SIG key
        try:
            mydevice.put_data("00C1", "132A8648CE3D030107")
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw_code == 0x6A80:
                raise Exception(
                    "This device is not compatible with ECDSA 256r1."
                ) from exc
            raise
        # Generate key for sign
        pubkey_card_all = mydevice.gen_key("B600")
    pubkey_card = pubkey_card_all[-65:]
    print('Device "SIG" public key read')

    PIN1 = "123456" #getpass.getpass("Enter PIN1 : ")

    # Make 200 ECDSA
    print(f"\nPublicKey for signature : 0x{pubkey_card.hex()}")
    message = "Hello SmartPGP! Take that message.".encode("ascii")
    hash = sha256(message)
    for _ in range(200):
        mydevice.verify_pin(1, PIN1)
        sig_card = mydevice.sign_ec_der(hash)
        print(f"Signature : 0x{sig_card.hex()}")
        if check_signature(message, sig_card, pubkey_card):
            print("OK")
        else:
            print("Can't check signature")
            return


if __name__ == "__main__":
    try:
        main()
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw_code == 0x6F00:
            print("Crash, game over.")
            print("SFYL !")
            print(exc)
