#!/usr/bin/env python


import smartcard


SELECT_APPLET = [0x00, 0xA4,
                 0x04, 0x00,
                 0x10,
                 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00]

TEST_RANDOM = [0x00, 0x00,
               0x00, 0x00];

TEST_RSA_1024_STATIC = [0x00, 0x01,
                        0x00, 0x00];

TEST_RSA_1024_GENERATE = [0x00, 0x01,
                          0x01, 0x00];

TEST_RSA_CRT_1024_STATIC = [0x00, 0x02,
                            0x00, 0x00];

TEST_RSA_CRT_1024_GENERATE = [0x00, 0x02,
                              0x01, 0x00];

TEST_RSA_2048_STATIC = [0x00, 0x01,
                        0x00, 0x01];

TEST_RSA_2048_GENERATE = [0x00, 0x01,
                          0x01, 0x01];

TEST_RSA_CRT_2048_STATIC = [0x00, 0x02,
                            0x00, 0x01];

TEST_RSA_CRT_2048_GENERATE = [0x00, 0x02,
                              0x01, 0x01];

TEST_RSA_3072_STATIC = [0x00, 0x01,
                        0x00, 0x02];

TEST_RSA_3072_GENERATE = [0x00, 0x01,
                          0x01, 0x02];

TEST_RSA_CRT_3072_STATIC = [0x00, 0x02,
                            0x00, 0x02];

TEST_RSA_CRT_3072_GENERATE = [0x00, 0x02,
                              0x01, 0x02];

TEST_RSA_4096_STATIC = [0x00, 0x01,
                        0x00, 0x03];

TEST_RSA_4096_GENERATE = [0x00, 0x01,
                          0x01, 0x03];

TEST_RSA_CRT_4096_STATIC = [0x00, 0x02,
                            0x00, 0x03];

TEST_RSA_CRT_4096_GENERATE = [0x00, 0x02,
                              0x01, 0x03];

TEST_EC_P256_STATIC = [0x00, 0x03,
                       0x00, 0x00];

TEST_EC_P256_STATIC_NO_W = [0x00, 0x03,
                            0x10, 0x00];

TEST_EC_P256_GENERATE = [0x00, 0x03,
                         0x01, 0x00];

TEST_EC_P521_STATIC = [0x00, 0x03,
                       0x00, 0x01];

TEST_EC_P521_GENERATE = [0x00, 0x03,
                         0x01, 0x01];

TEST_EC_P521_ALT_STATIC = [0x00, 0x03,
                           0x00, 0x11];

TEST_EC_P521_ALT_GENERATE = [0x00, 0x03,
                             0x01, 0x11];

TEST_PIN = [0x00, 0x04,
            0x00, 0x00,
            0x06,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36];


def assemble_with_len(prefix,data):
    return prefix + [len(data)] + data

def encode_len(data):
    l = len(data)
    if l > 0xff:
        l = [0x82, (l >> 8) & 0xff, l & 0xff]
    elif l > 0x7f:
        l = [0x81, l & 0xff]
    else:
        l = [l & 0xff]
    return l

def send_apdu(con, text, apdu):
    apdu = [int(c) for c in apdu]
    #print ' '.join('{:02X}'.format(c) for c in apdu)
    (data, sw1, sw2) = con.transmit(apdu)
    if sw1 == 0x90 and sw2 == 0x00:
        if text is not None:
            print "[+] %s... ok" % text
    else:
        if text is not None:
            print "[-] %s... KO 0x%02X%02X" % (text, sw1, sw2)
    return (data, sw1, sw2)

class InvalidCard(Exception):
    pass

def select_applet(con, show):
    text = None
    if show:
        text = "Select applet"
    (_, sw1, sw2) = send_apdu(con, text, SELECT_APPLET)
    if sw1 != 0x90 or sw2 != 0x00:
        raise InvalidCard
    
def test_random(con):
    select_applet(con, False)
    send_apdu(con, "Test random", TEST_RANDOM)

def test_rsa(con):
    select_applet(con, False)
    send_apdu(con, "Test RSA 1024 static", TEST_RSA_1024_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA 1024 generate", TEST_RSA_1024_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 1024 static", TEST_RSA_CRT_1024_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 1024 generate", TEST_RSA_CRT_1024_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA 2048 static", TEST_RSA_2048_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA 2048 generate", TEST_RSA_2048_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 2048 static", TEST_RSA_CRT_2048_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 2048 generate", TEST_RSA_CRT_2048_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA 3072 static", TEST_RSA_3072_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA 3072 generate", TEST_RSA_3072_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 3072 static", TEST_RSA_CRT_3072_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 3072 generate", TEST_RSA_CRT_3072_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA 4096 static", TEST_RSA_4096_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA 4096 generate", TEST_RSA_4096_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 4096 static", TEST_RSA_CRT_4096_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test RSA_CRT 4096 generate", TEST_RSA_CRT_4096_GENERATE)

def test_ec(con):
    select_applet(con, False)
    send_apdu(con, "Test NIST P-256 static", TEST_EC_P256_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-256 static (without W)", TEST_EC_P256_STATIC_NO_W)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-256 generate", TEST_EC_P256_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-521 static", TEST_EC_P521_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-521 generate", TEST_EC_P521_GENERATE)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-521 (size = 528) static", TEST_EC_P521_ALT_STATIC)
    select_applet(con, False)
    send_apdu(con, "Test NIST P-521 (size = 528) generate", TEST_EC_P521_ALT_GENERATE)

def test_pin(con):
    select_applet(con, False)
    (data, _, _) = send_apdu(con, "Test PIN", TEST_PIN);

def main():
    reader_list = smartcard.System.readers()
    r = reader_list[0]
    con = r.createConnection()
    con.connect()
    select_applet(con, True)
    test_random(con)
    test_rsa(con)
    test_ec(con)
    test_pin(con)

if __name__=='__main__':
    main()

