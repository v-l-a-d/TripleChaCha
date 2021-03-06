package com.github.vlad;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

/**
 */
public class TripleChaChaTest {

    private KeyGenerator keyGenerator;

    @Before
    public void setup() throws Exception {
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
    }

    @Test
    public void chaCha() {
        TripleChaCha chaCha = new TripleChaCha(keyGenerator.generateKey().getEncoded(), "initVector".getBytes());

        for (byte ii = 0; ii < 23; ii++) {
            byte[] value = new byte[2];
            value[1] = ii;

            System.out.println(Arrays.toString(value));
            chaCha.encrypt(value);
            System.out.println(Arrays.toString(value));
            chaCha.decrypt(value);
            System.out.println(Arrays.toString(value));
        }
    }

    @Test
    public void chaChaStrings() {
        TripleChaCha chaCha = new TripleChaCha(keyGenerator.generateKey().getEncoded(), "initVector".getBytes());

        String[] values = new String[] {
                "Hello", "Goodbye", "Good", "Food", "Foot", "aa", "ab", "ac", "ad", "aba", "abba"
        };

        for (String value : values) {
            byte[] bytes = value.getBytes();
            chaCha.encrypt(bytes);
            System.out.println(value + " = " + Arrays.toString(bytes));
            chaCha.decrypt(bytes);
            assertEquals(value, new String(bytes));
        }
    }

    @Test
    public void chaCha16digitIntegers() {
        TripleChaCha chaCha = new TripleChaCha(keyGenerator.generateKey().getEncoded(), "initVector".getBytes());

        BigInteger max = new BigInteger("9999999999999999");
        //System.out.println(Arrays.toString(max.toByteArray()));

        BigInteger val = new BigInteger("1539795333961248");
        byte[] bytes = val.toByteArray();
        System.out.println(Arrays.toString(bytes));

        do {
            chaCha.encrypt(bytes);
            System.out.println(Arrays.toString(bytes));
        } while (bytes[0] < 0 || bytes[0] >= 35);

        BigInteger result = new BigInteger(bytes);
        System.out.println(result.toString());

        bytes = result.toByteArray();
        System.out.println(Arrays.toString(bytes));
        do {
            chaCha.decrypt(bytes);
            System.out.println(Arrays.toString(bytes));
        } while (bytes[0] < 0 || bytes[0] >= 35);

        result = new BigInteger(bytes);
        System.out.println(result.toString());
    }

    @Test
    public void stats() {
        TripleChaCha chaCha = new TripleChaCha(keyGenerator.generateKey().getEncoded(), "initVector".getBytes());
        long[][] counts = new long[15][256];

        for (int ii = 100000; ii < 1000000; ii++) {
            byte[] bytes = ("val" + ii + "lav").getBytes();
            chaCha.encrypt(bytes);

            for (int jj = 0; jj < bytes.length; jj++) {
                counts[jj][bytes[jj] & 0xFF]++;
            }
        }

        double expected = 900000 / 256.0;

        for (int ii = 0; ii < counts.length; ii++) {
            double total = 0.0;
            for (int jj = 0; jj < counts[ii].length; jj++) {
                total += Math.abs(expected - counts[ii][jj]);
            }
            System.out.println(total / 256.0);
//            System.out.println(Arrays.toString(counts[ii]));


        }
    }
}