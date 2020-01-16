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

public final class CmacSignature {

    private CmacKey key;

    private final Cipher cipher;

    private final byte[] block_prev;
    private final byte[] block;

    private final byte[] bytes;
    private static final byte BYTE_OFFSET_BLOCK_LEN = 0;
    private static final byte BYTES_SIZE = BYTE_OFFSET_BLOCK_LEN + 1;


    protected CmacSignature() {
        key = null;

        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        block_prev = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);
        block = JCSystem.makeTransientByteArray(Constants.AES_BLOCK_SIZE, JCSystem.CLEAR_ON_DESELECT);

        bytes = JCSystem.makeTransientByteArray(BYTES_SIZE, JCSystem.CLEAR_ON_DESELECT);
    }

    protected final void clear() {
        if(key != null) {
            if(key.isInitialized()) {
                key.clearKey();
            }
            key = null;
        }
    }

    private final byte blockLen() {
        return bytes[BYTE_OFFSET_BLOCK_LEN];
    }

    private final void setBlockLen(final byte len) {
        bytes[BYTE_OFFSET_BLOCK_LEN] = len;
    }


    protected final boolean isInitialized() {
        return (key != null)
            && key.isInitialized();
    }

    private final void initBlock() {
        Util.arrayFillNonAtomic(block_prev, (short)0, (short)block_prev.length, (byte)0);
        Util.arrayFillNonAtomic(block, (short)0, (short)block.length, (byte)0);
        Util.arrayFillNonAtomic(bytes, (short)0, (short)bytes.length, (byte)0);
    }

    protected final void init(final CmacKey key) {
        if((key == null) || !key.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
            return;
        }

        this.key = key;

        cipher.init(key.key, Cipher.MODE_ENCRYPT);

        initBlock();
    }

    private final void commitBlock() {
        setBlockLen((byte)0);

        Common.arrayXor(block_prev, (short)0,
                        block, (short)0,
                        block, (short)0,
                        Constants.AES_BLOCK_SIZE);

        cipher.doFinal(block, (short)0, Constants.AES_BLOCK_SIZE,
                       block_prev, (short)0);
    }

    protected final void update(final byte[] inBuf, short inOff, short inLen) {

        if(!isInitialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
            return;
        }

        if(inLen <= 0) {
            return;
        }

        short bl = (short)blockLen();

        short remLen = (short)(Constants.AES_BLOCK_SIZE - bl);

        while(inLen >= remLen) {
            Util.arrayCopyNonAtomic(inBuf, inOff,
                                    block, bl,
                                    remLen);
            commitBlock();

            inLen -= remLen;
            inOff += remLen;

            remLen = Constants.AES_BLOCK_SIZE;
            bl = (short)0;
        }

        if(inLen > 0) {
            Util.arrayCopyNonAtomic(inBuf, inOff,
                                    block, bl,
                                    inLen);

            bl = (short)(bl + inLen);
        }

        setBlockLen((byte)bl);
    }

    protected final void updateByte(final byte b) {
        if(!isInitialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
            return;
        }

        short bl = blockLen();

        block[bl++] = b;

        if(bl == Constants.AES_BLOCK_SIZE) {
            commitBlock();
        } else {
            setBlockLen((byte)bl);
        }
    }

    protected final void updateShort(final short s) {
        updateByte((byte)((s >> 8) & (byte)0xff));
        updateByte((byte)(s & (byte)0xff));
    }

    private final void compute(final byte[] inBuf, short inOff, short inLen) {
        if(!isInitialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
            return;
        }

        if(inLen < 0) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            return;
        }

        short bl = blockLen();

        if(inLen > 0) {
            final short il = (short)(inLen - 1);

            update(inBuf, inOff, il);

            bl = blockLen();

            block[bl++] = inBuf[(short)(inOff + il)];

            setBlockLen((byte)bl);
        }

        if(bl == Constants.AES_BLOCK_SIZE) {
            Common.arrayXor(key.k1, (short)0,
                            block, (short)0,
                            block, (short)0,
                            Constants.AES_BLOCK_SIZE);
        } else {
            block[bl++] = (byte)0x80;
            Util.arrayFillNonAtomic(block, bl, (short)(Constants.AES_BLOCK_SIZE - bl), (byte)0);
            Common.arrayXor(key.k2, (short)0,
                            block, (short)0,
                            block, (short)0,
                            Constants.AES_BLOCK_SIZE);
        }

        commitBlock();
    }

    protected final short sign(final byte[] inBuf, short inOff, short inLen,
                               final byte[] sigBuf, final short sigOff, final short sigLen) {

        if(!isInitialized()) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
            return 0;
        }

        if((sigLen < 0) || (sigLen > Constants.AES_BLOCK_SIZE)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            return 0;
        }

        compute(inBuf, inOff, inLen);

        Util.arrayCopyNonAtomic(block_prev, (short)0,
                                sigBuf, sigOff,
                                sigLen);

        init(key);

        return sigLen;
    }

}
