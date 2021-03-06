/**
 MIT License

 Copyright (c) 2018 Vladimir Eatwell

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

package com.github.vlad;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 */
public class TripleChaCha {

    private final static int ENGINES = 7;

    private final ChaChaEngine[] engines;
    private final int[][] jumpTables;

    public TripleChaCha(byte[] key, byte[] iv) {
        if (key.length != 16) {
            throw new IllegalArgumentException("Key must be 128 bits");
        }
        if (iv.length < 8) {
            throw new IllegalArgumentException("IV must be at least 8 bytes");
        }

        // Set up engines
        this.engines = new ChaChaEngine[ENGINES];

        // Digest for key derivation
        SHA3Digest digest = new SHA3Digest(256);

        for (int ii = 0; ii < ENGINES; ii++) {
            this.engines[ii] = makeEngine(key, iv);

            // Derive next key
            digest.update(key, 0, key.length);
            digest.update(iv, 0, iv.length);

            byte[] tmp = new byte[32];
            digest.doFinal(tmp, 0);
            System.arraycopy(tmp, 0, key, 0, key.length);
        }

        // Setup jump table
        this.jumpTables = new int[ENGINES][256];

        for (int ii = 0; ii < 256; ii++) {
            for (int jj = 0; jj < ENGINES; jj++) {
                jumpTables[jj][ii] = engines[jj].returnByte((byte) 0) & 0xFF;
            }
        }
    }

    public void encrypt(byte[] value) {
        encrypt(value, 0, value.length);
    }

    public void encrypt(byte[] value, int offset, int length) {
        // Apply the 3 key-streams: forwards then backwards then forwards
        for (int ii = 0; ii < engines.length; ii++) {
            skipCrypt(ii, value, (ii % 2 != 0), true, offset, length);
        }
    }

    public void decrypt(byte[] value) {
        decrypt(value, 0, value.length);
    }

    public void decrypt(byte[] value, int offset, int length) {
        for (int ii = engines.length - 1; ii >= 0; ii--) {
            skipCrypt(ii, value, (ii % 2 != 0), false, offset, length);
        }
    }

    private void skipCrypt(int engine, byte[] value, boolean reverse, boolean encrypt, int offset, int length) {
        engines[engine].seekTo(256);

        int start = reverse ? offset + length - 1 : offset;
        int increment = reverse ? -1 : 1;

        for (int ii = start; (ii < offset + length) && (ii >= offset); ii += increment) {
            byte tmp = value[ii];
            value[ii] = engines[engine].returnByte(tmp);

            // Skip ahead in the key stream depending on the value
            int jump = encrypt ? value[ii] : tmp;
            engines[engine].skip(jumpTables[engine][jump & 0xFF]);
        }
    }

    private ChaChaEngine makeEngine(byte[] key, byte[] iv) {
        KeyParameter keyParameter = new KeyParameter(key);
        CipherParameters cipherParameters = new ParametersWithIV(keyParameter, iv, 0, 8);

        ChaChaEngine engine = new ChaChaEngine();
        engine.init(true, cipherParameters);
        return engine;
    }
}
