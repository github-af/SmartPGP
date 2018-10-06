package fr.anssi.smartpgp;


import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.*;
import javacardx.crypto.*;


public final class TestApplet extends Applet {


    private final byte[] buffer_red;
    private final byte[] buffer_black;

    public TestApplet() {
        buffer_red = JCSystem.makeTransientByteArray(Data.BUFFER_RED_LENGTH,
                                                     JCSystem.CLEAR_ON_DESELECT);
        buffer_black = JCSystem.makeTransientByteArray(Data.BUFFER_BLACK_LENGTH,
                                                       JCSystem.CLEAR_ON_DESELECT);
    }

    public static final void install(byte[] buf, short off, byte len) {
        new TestApplet().register();
    }

    private final void processTestRandom(final byte p1, final byte p2) {
        final RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rand.generateData(buffer_red, (short)0, (short)buffer_red.length);
    }

    private final void processTestRsa(final boolean crt, final byte p1, final byte p2) {
        boolean generate;
        short size;
        PrivateKey priv;
        RSAPublicKey pub;
        byte[] p, q, pq, dp1, dq1, n, e, d;

        switch(p1) {
        case (byte)0x00:
            generate = false;
            break;

        case (byte)0x01:
            generate = true;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        switch(p2) {
        case (byte)0x00:
            size = (short)1024;
            p = Data.RSA_1024_PRIV_PRIME_P;
            q = Data.RSA_1024_PRIV_PRIME_Q;
            pq = Data.RSA_1024_PRIV_PQ;
            dp1 = Data.RSA_1024_PRIV_EXPONENT_DP1;
            dq1 = Data.RSA_1024_PRIV_EXPONENT_DQ1;
            n = Data.RSA_1024_PUB_MODULUS_N;
            e = Data.RSA_1024_PUB_EXPONENT_E;
            d = Data.RSA_1024_PRIV_EXPONENT_D;
            break;

        case (byte)0x01:
            size = (short)2048;
            p = Data.RSA_2048_PRIV_PRIME_P;
            q = Data.RSA_2048_PRIV_PRIME_Q;
            pq = Data.RSA_2048_PRIV_PQ;
            dp1 = Data.RSA_2048_PRIV_EXPONENT_DP1;
            dq1 = Data.RSA_2048_PRIV_EXPONENT_DQ1;
            n = Data.RSA_2048_PUB_MODULUS_N;
            e = Data.RSA_2048_PUB_EXPONENT_E;
            d = Data.RSA_2048_PRIV_EXPONENT_D;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, size, false);

        if(pub == null) {
            ISOException.throwIt(Data.SW_FAILED_TO_BUILD_PUB_KEY);
            return;
        }

        if(crt) {
            priv = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, size, false);
            if(!generate) {
                ((RSAPrivateCrtKey)priv).setP(p, (short)0, (short)p.length);
                ((RSAPrivateCrtKey)priv).setQ(q, (short)0, (short)q.length);
                ((RSAPrivateCrtKey)priv).setPQ(pq, (short)0, (short)pq.length);
                ((RSAPrivateCrtKey)priv).setDP1(dp1, (short)0, (short)dp1.length);
                ((RSAPrivateCrtKey)priv).setDQ1(dq1, (short)0, (short)dq1.length);
                pub.setModulus(n, (short)0, (short)n.length);
                pub.setExponent(e, (short)0, (short)e.length);
            }
        } else {
            priv = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, size, false);
            if(!generate) {
                ((RSAPrivateKey)priv).setModulus(n, (short)0, (short)n.length);
                ((RSAPrivateKey)priv).setExponent(d, (short)0, (short)d.length);
                pub.setModulus(n, (short)0, (short)n.length);
                pub.setExponent(e, (short)0, (short)e.length);
            }
        }

        if(priv == null) {
            ISOException.throwIt(Data.SW_FAILED_TO_BUILD_PRIV_KEY);
            return;
        }

        if(generate) {
            final KeyPair kp = new KeyPair(pub, priv);
            kp.genKeyPair();
        }

        if(!pub.isInitialized()) {
            ISOException.throwIt(Data.SW_PUB_KEY_NOT_INITIALIZED);
            return;
        }

        if(!priv.isInitialized()) {
            ISOException.throwIt(Data.SW_PRIV_KEY_NOT_INITIALIZED);
            return;
        }

        final Cipher cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        cipher_rsa_pkcs1.init(pub, Cipher.MODE_ENCRYPT);
        cipher_rsa_pkcs1.doFinal(buffer_red, (short)0, (short)64,
                                 buffer_black, (short)0);

        cipher_rsa_pkcs1.init(priv, Cipher.MODE_DECRYPT);
        cipher_rsa_pkcs1.doFinal(buffer_black, (short)0, (short)(size / 8),
                                 buffer_red, (short)0);
    }

    private final void processTestEc(final byte p1, final byte p2) {
        boolean generate;
        short size;
        ECPrivateKey priv;
        ECPublicKey pub;
        byte[] field, a, b, g, r, s, w;
        short k;

        switch(p1) {
        case (byte)0x00:
            generate = false;
            break;

        case (byte)0x01:
            generate = true;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        switch(p2) {
        case (byte)0x00:
            size = 256;
            field = ECConstants.ansix9p256r1_field;
            a = ECConstants.ansix9p256r1_a;
            b = ECConstants.ansix9p256r1_b;
            g = ECConstants.ansix9p256r1_g;
            r = ECConstants.ansix9p256r1_r;
            k = (short)1;
            s = Data.EC_ANSIX9P256R1_S;
            w = Data.EC_ANSIX9P256R1_W;
            break;

        case (byte)0x01:
            size = 521;
            field = ECConstants.ansix9p521r1_field;
            a = ECConstants.ansix9p521r1_a;
            b = ECConstants.ansix9p521r1_b;
            g = ECConstants.ansix9p521r1_g;
            r = ECConstants.ansix9p521r1_r;
            k = (short)1;
            s = Data.EC_ANSIX9P521R1_S;
            w = Data.EC_ANSIX9P521R1_W;
            break;

        case (byte)0x11:
            size = 528;
            field = ECConstants.ansix9p521r1_field;
            a = ECConstants.ansix9p521r1_a;
            b = ECConstants.ansix9p521r1_b;
            g = ECConstants.ansix9p521r1_g;
            r = ECConstants.ansix9p521r1_r;
            k = (short)1;
            s = Data.EC_ANSIX9P521R1_S;
            w = Data.EC_ANSIX9P521R1_W;
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
            return;
        }

        pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, size, false);

        if(pub == null) {
            ISOException.throwIt(Data.SW_FAILED_TO_BUILD_PUB_KEY);
            return;
        }

        pub.setFieldFP(field, (short)0, (short)field.length);
        pub.setA(a, (short)0, (short)a.length);
        pub.setB(b, (short)0, (short)b.length);
        pub.setG(g, (short)0, (short)g.length);
        pub.setR(r, (short)0, (short)r.length);
        pub.setK(k);

        priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, size, false);

        if(priv == null) {
            ISOException.throwIt(Data.SW_FAILED_TO_BUILD_PRIV_KEY);
            return;
        }

        priv.setFieldFP(field, (short)0, (short)field.length);
        priv.setA(a, (short)0, (short)a.length);
        priv.setB(b, (short)0, (short)b.length);
        priv.setG(g, (short)0, (short)g.length);
        priv.setR(r, (short)0, (short)r.length);
        priv.setK(k);

        if(generate) {
            final KeyPair kp = new KeyPair(pub, priv);
            kp.genKeyPair();
        } else {
            priv.setS(s, (short)0, (short)s.length);
            pub.setW(w, (short)0, (short)w.length);
        }

        if(!pub.isInitialized()) {
            ISOException.throwIt(Data.SW_PUB_KEY_NOT_INITIALIZED);
            return;
        }

        if(!priv.isInitialized()) {
            ISOException.throwIt(Data.SW_PRIV_KEY_NOT_INITIALIZED);
            return;
        }

        final Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
        sig.init(priv, Signature.MODE_SIGN);

        sig.signPreComputedHash(buffer_red, (short)0, MessageDigest.LENGTH_SHA_512,
                                buffer_black, (short)0);
    }

    public final void process(final APDU apdu) {
        final byte[] apdubuf = apdu.getBuffer();

        if(apdu.isISOInterindustryCLA() && selectingApplet()) {
            return;
        }

        final byte p1 = apdubuf[ISO7816.OFFSET_P1];
        final byte p2 = apdubuf[ISO7816.OFFSET_P2];

        switch(apdubuf[ISO7816.OFFSET_INS]) {
        case Data.INS_TEST_RANDOM:
            processTestRandom(p1, p2);
            break;

        case Data.INS_TEST_RSA:
            processTestRsa(false, p1, p2);
            break;

        case Data.INS_TEST_RSA_CRT:
            processTestRsa(true, p1, p2);
            break;

        case Data.INS_TEST_EC:
            processTestEc(p1, p2);
            break;

        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            return;
        }
    }
}
