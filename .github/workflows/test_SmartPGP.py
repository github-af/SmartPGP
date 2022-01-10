#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from sys import path
import subprocess
import getpass
import hashlib
import tempfile


path.append(".")
import OpenPGPpy


class BadTestResult(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).digest()


def rsa_2048_pubkey_to_der(pubkey):
    # Add ASN1 DER header
    # RSA 2048
    header_modulus = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
    header_exponent = "0203"

    modulus = pubkey[9:265].hex()
    exponent = pubkey[267:].hex()

    return bytes.fromhex(header_modulus + modulus + header_exponent + exponent)


def check_rsa_2048_signature(message, signature, pubkeyd):
    pubkey = rsa_2048_pubkey_to_der(pubkeyd)
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
            verify_cmd, input=message, shell=True, check=True, stdout=subprocess.PIPE
        )
        sigOK = True
    except Exception:
        print("[-] ERROR in signature verification:")
        print(">>> openssl is required in path to check signatures")
        sigOK = False
    os.remove(fpk.name)
    os.remove(fsig.name)
    return sigOK


def encrypt_rsa_2048(message, pubkeyd):
    pubkey = rsa_2048_pubkey_to_der(pubkeyd)
    fpk = tempfile.NamedTemporaryFile(delete=False)
    fpk.write(pubkey)
    fpk.close()
    fenc = tempfile.NamedTemporaryFile(delete=False)
    fenc.close()
    encrypt_cmd = (
        f"openssl rsautl -keyform DER -pubin -inkey {fpk.name} -pkcs -encrypt -out {fenc.name}"
    )
    try:
        subprocess.run(
            encrypt_cmd, input=message, shell=True, check=True, stdout=subprocess.PIPE
        )
    except Exception:
        print("[-] ERROR in encrpytion")
        print(">>> openssl is required in path to encrypt message")
        raise
    os.remove(fpk.name)
    fres = open(fenc.name, 'rb')
    res = fres.read()
    fres.close()
    os.remove(fenc.name)
    return bytes.fromhex("00") + res


def test_rsa_2048_signature(token, PIN1, PIN3, repeat):
    print(f"[+] == Test RSA 2048 signature ({repeat} signatures) ==")

    # Verify PIN3, required for the next command
    print("[+] Verify PIN3")
    token.verify_pin(3, PIN3)

    # Setup RSA 2048 for SIG key
    print("[+] Set SIG key to RSA 2048")
    token.put_data("00C1", "010800001103")

    # Generate key for SIG key
    print("[+] Generate SIG key")
    pubkey_card = token.gen_key("B600")

    # Digest message and sign
    message = "Hello SmartPGP! Take that message.".encode("ascii")
    header_sha256 = "3031300D060960864801650304020105000420";
    hash = bytes.fromhex(header_sha256) + sha256(message)

    for i in range(repeat):
        print(f"[+] Test #{i + 1}")

        # Verify PIN1, required for signature
        token.verify_pin(1, PIN1)

        print("[+] Sign SHA256 hash")
        sig_card = token.sign(hash)

        print("[+] Verify signature")
        if not check_rsa_2048_signature(message, sig_card, pubkey_card):
            print("[-] BAD signature")
            raise BadTestResult


def test_rsa_2048_decrypt(token, PIN1, PIN3, repeat):
    print(f"[+] == Test RSA 2048 decrypt ({repeat} deciphers) ==")

    # Verify PIN3, required for the next command
    print("[+] Verify PIN3")
    token.verify_pin(3, PIN3)

    # Setup RSA 2048 for DEC key
    print("[+] Set DEC key to RSA 2048")
    token.put_data("00C2", "010800001103")

    # Generate key for DEC key
    print("[+] Generate DEC key")
    pubkey_card = token.gen_key("B800")

    # Verify PIN2, required for decrypt
    token.verify_pin(2, PIN1)

    # Cipher message
    message = "Hello SmartPGP! Take that message.".encode("ascii")

    print("[+] Prepare encrypted message")
    encrypted = encrypt_rsa_2048(message, pubkey_card)

    for i in range(repeat):
        print(f"[+] Test #{i + 1}")

        print("[+] Decipher message")
        decrypted = token.decipher(encrypted)

        print("[+] Verify message")
        if message == decrypted:
            print("[+] Good deciphering")
        else:
            print("[-] BAD deciphering")
            raise BadTestResult


def test_rsa_2048(token, PIN1, PIN3, repeat):
    print("[+] === Test RSA 2048 ===")

    test_rsa_2048_signature(token, PIN1, PIN3, repeat)

    test_rsa_2048_decrypt(token, PIN1, PIN3, repeat)


def ec_prime256v1_pubkey_to_der(pubkey):
    # Add ASN1 DER header (EC parameters)
    # ECP 256 r1 header
    header_hex = "3059301306072A8648CE3D020106082A8648CE3D030107034200"
    return bytes.fromhex(header_hex + pubkey.hex())


def check_ec_prime256v1_signature(message, signature, pubkeyd):
    pubkey = ec_prime256v1_pubkey_to_der(pubkeyd)
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
            verify_cmd, input=message, shell=True, check=True, stdout=subprocess.PIPE
        )
        sigOK = True
    except Exception:
        print("[-] ERROR in signature verification")
        print(">>> openssl is required in path to check signatures")
        sigOK = False
    os.remove(fpk.name)
    os.remove(fsig.name)
    return sigOK


def encrypt_ec_prime256v1(pubkeyd):
    pubkey = ec_prime256v1_pubkey_to_der(pubkeyd)
    fpub = tempfile.NamedTemporaryFile(delete=False)
    fpub.write(pubkey)
    fpub.close()

    fpriv2 = tempfile.NamedTemporaryFile(delete=False)
    fpriv2.close()
    generate_private_cmd = (
        f"openssl genpkey -outform DER -out {fpriv2.name} -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve"
    )
    try:
        subprocess.run(
            generate_private_cmd, shell=True, check=True, stdout=subprocess.PIPE
        )
    except Exception:
        print("[-] ERROR in encrpytion")
        print(">>> openssl is required in path to encrypt message")
        raise

    fpub2 = tempfile.NamedTemporaryFile(delete=False)
    fpub2.close()
    generate_pub_cmd = (
        f"openssl pkey -pubout -inform DER -in {fpriv2.name} -outform DER -out {fpub2.name}"
    )
    try:
        subprocess.run(
            generate_pub_cmd, shell=True, check=True, stdout=subprocess.PIPE
        )
    except Exception:
        print("[-] ERROR in encrpytion")
        print(">>> openssl is required in path to encrypt message")
        raise

    fenc = tempfile.NamedTemporaryFile(delete=False)
    fenc.close()
    generate_ecdh_cmd = (
        f"openssl pkeyutl -derive -out {fenc.name} -keyform DER -inkey {fpriv2.name} -peerform DER -peerkey {fpub.name}"
    )
    try:
        subprocess.run(
            generate_ecdh_cmd, shell=True, check=True, stdout=subprocess.PIPE
        )
    except Exception:
        print("[-] ERROR in encrpytion")
        print(">>> openssl is required in path to encrypt message")
        raise

    f = open(fpub2.name, 'rb')
    pub2 = f.read()
    pub2 = pub2[26:]
    f.close()

    f = open(fenc.name, 'rb')
    enc = f.read()
    f.close()

    os.remove(fpub.name)
    os.remove(fpriv2.name)
    os.remove(fpub2.name)
    os.remove(fenc.name)

    return (bytes.fromhex("A646") + bytes.fromhex("7F4943") + bytes.fromhex("8641") + pub2, enc)


def test_ec_prime256v1_signature(token, PIN1, PIN3, repeat):
    print(f"[+] == Test EC prime256v1 signature ({repeat} signatures) ==")

    # Verify PIN3, required for the next command
    print("[+] Verify PIN3")
    token.verify_pin(3, PIN3)

    # Setup EC prime256v1 for SIG key
    print("[+] Set SIG key to EC prime256v1")
    token.put_data("00C1", "132A8648CE3D030107")

    # Generate key for SIG key
    print("[+] Generate SIG key")
    pubkey_card = token.gen_key("B600")
    pubkey_card = pubkey_card[-65:]

    # Digest message and sign
    message = "Hello SmartPGP! Take that message.".encode("ascii")
    hash = sha256(message)

    for i in range(repeat):
        print(f"[+] Test #{i + 1}")

        # Verify PIN1, required for signature
        token.verify_pin(1, PIN1)

        print("[+] Sign SHA256 hash")
        sig_card = token.sign_ec_der(hash)

        print("[+] Verify signature")
        if not check_ec_prime256v1_signature(message, sig_card, pubkey_card):
            print("[-] BAD signature")
            raise BadTestResult


def test_ec_prime256v1_decrypt(token, PIN1, PIN3, repeat):
    print(f"[+] == Test EC prime256v1 decrypt ({repeat} deciphers) ==")

    # Verify PIN3, required for the next command
    print("[+] Verify PIN3")
    token.verify_pin(3, PIN3)

    # Setup EC prime256v1 for DEC key
    print("[+] Set DEC key to EC prime256v1")
    token.put_data("00C2", "122A8648CE3D030107")

    # Generate key for DEC key
    print("[+] Generate DEC key")
    pubkey_card = token.gen_key("B800")
    pubkey_card = pubkey_card[-65:]

    # Verify PIN2, required for decrypt
    token.verify_pin(2, PIN1)

    print("[+] Prepare ECDH")
    (encrypted, secret) = encrypt_ec_prime256v1(pubkey_card)

    for i in range(repeat):
        print(f"[+] Test #{i + 1}")

        print("[+] Decipher (compute ECDH secret)")
        decrypted = token.decipher(encrypted)

        print("[+] Verify message")
        if secret == decrypted:
            print("[+] Good deciphering")
        else:
            print("[-] BAD deciphering")
            raise BadTestResult


def test_ec_prime256v1(token, PIN1, PIN3, repeat):
    print("[+] === Test EC prime256v1 ===")

    test_ec_prime256v1_signature(token, PIN1, PIN3, repeat)

    test_ec_prime256v1_decrypt(token, PIN1, PIN3, repeat)


def main(rsa, ec, repeat):
    # True/False == with/without debug
    token = OpenPGPpy.OpenPGPcard(False)

    PIN1 = "123456"
    PIN3 = "12345678"

    if rsa:
        test_rsa_2048(token, PIN1, PIN3, repeat)

    if ec:
        test_ec_prime256v1(token, PIN1, PIN3, repeat)


if __name__ == "__main__":
    try:
        main(rsa=True, ec=True, repeat=200)
    except OpenPGPpy.openpgp_card.ConnectionException:
        print(f"[-] FAILED to find OpenPGP token")
        exit(1)
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw_code != 0x9000:
            print(f"[-] FAILED with: 0x{exc.sw_code:02x}")
        exit(2)
    except BadTestResult:
        print(f"[-] FAILED test")
        exit(3)
