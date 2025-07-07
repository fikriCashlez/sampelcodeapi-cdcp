package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;

import static java.sql.DriverManager.println;
import static org.example.Main.*;

public class DUKPTUtil {
    // When AND'ed to a 10 byte KSN, zeroes all the 21 bits of the transaction
    // counter
    public static final String KSN_MASK = "FF FF FF FF FF FF FF E0 00 00";
    // When AND'ed to a 10 byte KSN, zeroes all 59 most significative bits,
    // preserving only the 21 bits of the transaction counter
    public static final String TRANSACTION_COUNTER_MASK = "00 00 00 00 00 00 00 1F FF FF";
    // Used for deriving IPEK and future keys
    public static final String BDK_MASK = "C0 C0 C0 C0 00 00 00 00 C0 C0 C0 C0 00 00 00 00";
    private static final String PIN_ENCRYPTION_VARIANT_CONSTANT = "00 00 00 00 00 00 00 FF";
    private static final String DATA_ENCRYPTION_VARIANT_CONSTANT_BOTH_WAYS = "00 00 00 00 00 FF 00 00";

    private static final String SHIFTR = "00 00 00 00 00 10 00 00";

    /**
     * Generates an IPEK
     *
     * @param KSN 10 bytes array (if your SNK has less than 10 bytes, pad it
     *            with 0xFF bytes to the left).
     * @param BDK 24 bytes array. It's a triple-key (mandatory for TDES), and
     *            each key has 8 bytes. In DUKPT, double-keys are uses, so
     *            K1 = K3 (ex. K1 = 01 23 45 67 89 AB CD EF, K2 = FE DC BA 98 76 54 32 10,
     *            K3 = K1 =  01 23 45 67 89 AB CD EF)
     * @return a 16 byte IPEK for a specific device (the one associated with the
     * serial key number in KSN), containing both the serial number and
     * the ID of the associated BDK The BDK format is usually like
     * follows: FF FF | BDK_ID[6] | TRSM_SN[5] | COUNTER[5] Note that
     * the rightmost bit of TRSM_ID must not be used, for it belongs to
     * the COUNTER. So the bytes of TRSM_SN must always form a multiple
     * of 2 value
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    public static byte[] generateIPEK(byte[] KSN, byte[] BDK)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException,
            InvalidAlgorithmParameterException {
        // 1) Copy the entire key serial number, including the 21-bit encryption counter, right-justified into a 10-byte register. If the key serial
        // number is less than 10 bytes, pad to the left with ExtensionKt "FF" bytes.

        // 2) Set the 21 least-significant bits of this 10-byte register to zero.
        byte[] KSN_mask = hexStringToBytes(KSN_MASK);
        byte[] masked_KSN = ByteArrayUtil.and(KSN, KSN_mask);

        // 3) Take the 8 most-significant bytes of this 10-byte register, and encrypt/decrypt/encrypt these 8 bytes using the double-length
        // derivation key, per the TECB mode of Reference 2.
        byte[] eigth_byte_masked_KSN = new byte[8];
        for (int i = 0; i < 8; i++) {
            eigth_byte_masked_KSN[i] = masked_KSN[i];
        }

        //byte[] IPEK_left = DESCryptoUtil.tdesEncrypt(eigth_byte_masked_KSN, BDK);
        byte[] IPEK_left = encrypt3DESECB(eigth_byte_masked_KSN, BDK);

        // 4) Use the cipher text produced by Step 3 as the left half of the
        // Initial Key.
        byte[] IPEK = new byte[16];
        for (int i = 0; i < 8; i++) {
            IPEK[i] = IPEK_left[i];
        }

        // 5) Take the 8 most-significant bytes from the 10-byte register of step 2 and encrypt/decrypt/encrypt these 8 bytes using as the key the
        // double-length derivation key XORed with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000, per the TECB mode of Reference 2.
        byte[] derivation_mask = hexStringToBytes(BDK_MASK);
        byte[] masked_derivation_key = ByteArrayUtil.xor(BDK, derivation_mask);
        //byte[] IPEK_right = DESCryptoUtil.tdesEncrypt(eigth_byte_masked_KSN, masked_derivation_key);
        byte[] IPEK_right = encrypt3DESECB(eigth_byte_masked_KSN, masked_derivation_key);

        // 6) Use the cipher text produced by Step 5 as the right half of the Initial Key.
        for (int i = 0; i < 8; i++) {
            IPEK[i + 8] = IPEK_right[i];
        }

        return IPEK;
    }

    /**
     * @param ksn ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12 34)
     * @return the ksn with it's last 21 bits set to 0. (ex. FF FF 98 76 54 32 10 E0 00 00)
     */
    public static byte[] ksnWithZeroedTransactionCounter(byte[] ksn) {
        return ByteArrayUtil.and(ksn, hexStringToBytes(KSN_MASK));
    }

    /**
     * @return the value of the ksnl's last 21 bits, right justified and padded to left with zeroes, as a 8 byte array (ex. 00 00 00 00 00 00 00 00 12 34)
     * @para_m ksn ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12 34)
     */
    public static byte[] extractTransactionCounterFromKSN(byte[] baKSN) {
        return ByteArrayUtil.subArray(
                ByteArrayUtil.and(baKSN, hexStringToBytes(TRANSACTION_COUNTER_MASK)), 2, 9);
    }

    /**
     * Given a Base Derivation Key and a KSN, derives Session Key that matches the encryption counter (21 rightmost bits of the KSN)
     *
     * @param ksn ten byte array, which 2 leftmost bytes value is 0xFF (ex. FF FF 98 76 54 32 10 E0 12 34)
     * @param bdk 16 bytes array (double-length key)
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] deriveKey(byte[] ksn, byte[] bdk)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, NoSuchPaddingException,
            InvalidAlgorithmParameterException {
        // 4) Store the Key Serial Number, as received, in the externally
        // initiated command, into the Key Serial Number Register.
        // 5) Clear the encryption counter (21st right-most bits of KSNR
        byte[] r3 = DUKPTUtil.extractTransactionCounterFromKSN(ksn);
        byte[] r8 = ByteArrayUtil.subArray(
                DUKPTUtil.ksnWithZeroedTransactionCounter(ksn), 2, 9);
        byte[] shiftr = hexStringToBytes(SHIFTR);
        byte[] crypto_register_1 = ByteArrayUtil.subArray(
                DUKPTUtil.ksnWithZeroedTransactionCounter(ksn), 2, 9);
        byte[] curKey = bdk;

        curKey = DUKPTUtil.generateIPEK(ksn, curKey);
        String hsIPEK = toHexString(curKey, 0, curKey.length, false);
        //System.out.println("hsIPEK: "+ hsIPEK);

        BigInteger intShiftr = new BigInteger(shiftr);
        BigInteger zero = new BigInteger("0");

        while (intShiftr.compareTo(zero) == 1) {
            byte[] temp = ByteArrayUtil.and(shiftr, r3);
            BigInteger intTemp = new BigInteger(temp);

            if (intTemp.compareTo(zero) == 1) {
                r8 = ByteArrayUtil.or(r8, shiftr);
                // crypto_register_1 =
                // ByteArrayUtil.or(ByteArrayUtil.createSubArray(DUKPTUtil.ksnWithZeroedTransactionCounter(ksn),
                // 2, 9)/*crypto_register_1*/, shiftr);

                // 1) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-2.
                byte[] crypto_register_2 = ByteArrayUtil.xor(
                        r8/* crypto_register_1 */,
                        ByteArrayUtil.subArray(curKey, 8, 15));

                // 2) Crypto Register-2 DEA-encrypted using, as the key, the
                // left half of the Key Register goes to Crypto Register-2.
                crypto_register_2 = desEncrypt(crypto_register_2,
                        ByteArrayUtil.subArray(curKey, 0, 7));

                // 3) Crypto Register-2 XORed with the right half of the Key
                // Register goes to Crypto Register-2.
                crypto_register_2 = ByteArrayUtil.xor(crypto_register_2,
                        ByteArrayUtil.subArray(curKey, 8, 15));

                // 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000
                // C0C0 C0C0 0000 0000.
                curKey = ByteArrayUtil.xor(curKey,
                        hexStringToBytes(BDK_MASK));

                // 5) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-1.
                crypto_register_1 = ByteArrayUtil.xor(
                        r8/* crypto_register_1 */,
                        ByteArrayUtil.subArray(curKey, 8, 15));

                // 6) Crypto Register-1 DEA-encrypted using, as the key, the
                // left half of the Key Register goes to Crypto Register-1.
                crypto_register_1 = desEncrypt(crypto_register_1,
                        ByteArrayUtil.subArray(curKey, 0, 7));

                // 7) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-1.
                crypto_register_1 = ByteArrayUtil.xor(crypto_register_1,
                        ByteArrayUtil.subArray(curKey, 8, 15));

                curKey = ByteArrayUtil.join(crypto_register_1,
                        crypto_register_2);
            }

            shiftr = ByteArrayUtil.shiftRight(shiftr, 1);
            intShiftr = new BigInteger(shiftr);
        }

        return curKey;
    }

    public static byte[] deriveKeyWithIPEK(byte[] baKSN, byte[] baIPEK) {

        String hsBuffer;

        // 4) Store the Key Serial Number, as received, in the externally
        // initiated command, into the Key Serial Number Register.
        // 5) Clear the encryption counter (21st right-most bits of KSNR
        byte[] baR3 = DUKPTUtil.extractTransactionCounterFromKSN(baKSN);
        String hsR3 = toHexString(baR3).toUpperCase();
        //System.out.println("hsR3: " + hsR3);

        byte[] baR8 = ByteArrayUtil.subArray(DUKPTUtil.ksnWithZeroedTransactionCounter(baKSN), 2, 9);
        String hsR8 = toHexString(baR8).toUpperCase();
        //System.out.println("hsR8: " + hsR8);

        byte[] baShiftR = hexStringToBytes(SHIFTR);
        String hsShiftR = toHexString(baShiftR).toUpperCase();
        //System.out.println("hsShiftR: " + hsShiftR);

        byte[] baCryptoRegister1 = ByteArrayUtil.subArray(DUKPTUtil.ksnWithZeroedTransactionCounter(baKSN), 2, 9);
        String hsCryptoRegister1 = toHexString(baCryptoRegister1).toUpperCase();
        //System.out.println("hsCryptoRegister1: " + hsCryptoRegister1);

        byte[] baCurKey = baIPEK;
        hsBuffer = toHexString(baCurKey).toUpperCase();
        //System.out.println("baCurKey = baIPEK: " + hsBuffer);

        BigInteger biShiftR = new BigInteger(baShiftR);
        //System.out.println("biShiftR: " + biShiftR);

        BigInteger biZero = new BigInteger("0");
        //System.out.println("biZero: " + biZero);

        while (biShiftR.compareTo(biZero) == 1) {
            byte[] baTemp = ByteArrayUtil.and(baShiftR, baR3);
            hsBuffer = toHexString(baTemp).toUpperCase();
            //System.out.println("baShiftR and baR3: " + hsBuffer);

            BigInteger biTemp = new BigInteger(baTemp);
            //System.out.println("biTemp: "+ biTemp);

            if (biTemp.compareTo(biZero) == 1) {
                baR8 = ByteArrayUtil.or(baR8, baShiftR);
                hsBuffer = toHexString(baR8).toUpperCase();
                //System.out.println("baR8 or baShiftR: " + hsBuffer);
                // baCryptoRegister1 =
                // ByteArrayUtil.or(ByteArrayUtil.createSubArray(DUKPTUtil.ksnWithZeroedTransactionCounter(baKSN),
                // 2, 9)/*crypto_register_1*/, baShiftR);

                // 1) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-2.
                byte[] baCryptoRegister2 = ByteArrayUtil.xor(baR8/* crypto_register_1 */, ByteArrayUtil.subArray(baCurKey, 8, 15));
                String hsCryptoRegister2 = toHexString(baCryptoRegister2).toUpperCase();
                //System.out.println("hsCryptoRegister2: " + hsCryptoRegister2);

                // 2) Crypto Register-2 DEA-encrypted using, as the key, the
                // left half of the Key Register goes to Crypto Register-2.
                try {
                    baCryptoRegister2 = desEncrypt(baCryptoRegister2, ByteArrayUtil.subArray(baCurKey, 0, 7));
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
                hsBuffer = toHexString(baCryptoRegister2).toUpperCase();
                //System.out.println("des encrypt baCryptoRegister2: " + hsBuffer);

                // 3) Crypto Register-2 XORed with the right half of the Key
                // Register goes to Crypto Register-2.
                baCryptoRegister2 = ByteArrayUtil.xor(baCryptoRegister2, ByteArrayUtil.subArray(baCurKey, 8, 15));
                hsBuffer = toHexString(baCryptoRegister2).toUpperCase();
                //System.out.println("encrypted baCryptoRegister2 xor with baCurKey: " + hsBuffer);

                // 4) XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000
                // C0C0 C0C0 0000 0000.
                baCurKey = ByteArrayUtil.xor(baCurKey, hexStringToBytes(BDK_MASK));
                hsBuffer = toHexString(baCurKey).toUpperCase();
                //System.out.println("xor baCurKey with BDK_MASK: " + hsBuffer);

                // 5) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-1.
                baCryptoRegister1 = ByteArrayUtil.xor(baR8/* crypto_register_1 */, ByteArrayUtil.subArray(baCurKey, 8, 15));
                hsCryptoRegister1 = toHexString(baCryptoRegister1).toUpperCase();
                //System.out.println("hsCryptoRegister1: " + hsCryptoRegister1);

                // 6) Crypto Register-1 DEA-encrypted using, as the key, the
                // left half of the Key Register goes to Crypto Register-1.
                try {
                    baCryptoRegister1 = desEncrypt(baCryptoRegister1, ByteArrayUtil.subArray(baCurKey, 0, 7));
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
                hsBuffer = toHexString(baCryptoRegister1).toUpperCase();
                //System.out.println("des encrypt baCryptoRegister1: " + hsBuffer);

                // 7) Crypto Register-1 XORed with the right half of the Key
                // Register goes to Crypto Register-1.
                baCryptoRegister1 = ByteArrayUtil.xor(baCryptoRegister1, ByteArrayUtil.subArray(baCurKey, 8, 15));
                hsBuffer = toHexString(baCryptoRegister1).toUpperCase();
                //System.out.println("encrypted baCryptoRegister1 xor with baCurKey: " + hsBuffer);

                baCurKey = ByteArrayUtil.join(baCryptoRegister1, baCryptoRegister2);
                hsBuffer = toHexString(baCurKey).toUpperCase();
                //System.out.println("baCryptoRegister1 + baCryptoRegister2: " + hsBuffer);
            }

            baShiftR = ByteArrayUtil.shiftRight(baShiftR, 1);
            hsBuffer = toHexString(baShiftR).toUpperCase();
            //System.out.println("shift right baShiftR 1 time: "+ hsBuffer);

            biShiftR = new BigInteger(baShiftR);
            //System.out.println("biShiftR: "+ biShiftR);

            //System.out.println();
        }

        return baCurKey;
    }


    public static byte[] calculateDataEncryptionKey(byte[] derivedKey) {
        byte[] variant_constant = hexStringToBytes(DATA_ENCRYPTION_VARIANT_CONSTANT_BOTH_WAYS);
        byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
        byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);

        // 1 - derivedKey_L XOR pin_variant_constant = pin_key_L
        byte[] pin_key_L = ByteArrayUtil.xor(derivedKeyL, variant_constant);

        // 2 - derivedKey_R XOR pin_variant_constant_R = pin_key_R
        byte[] pin_key_R = ByteArrayUtil.xor(derivedKeyR, variant_constant);

        return ByteArrayUtil.join(pin_key_L, pin_key_R);
    }


    public static byte[] calculatePinEncryptionKey(byte[] derivedKey) {
        byte[] variant_constant = hexStringToBytes(PIN_ENCRYPTION_VARIANT_CONSTANT);
        byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
        byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);

        // 1 - derivedKey_L XOR pin_variant_constant = pin_key_L
        byte[] pin_key_L = ByteArrayUtil.xor(derivedKeyL, variant_constant);

        // 2 - derivedKey_R XOR pin_variant_constant_R = pin_key_R
        byte[] pin_key_R = ByteArrayUtil.xor(derivedKeyR, variant_constant);

        return ByteArrayUtil.join(pin_key_L, pin_key_R);
    }


    public static byte[] decryptTrackWithIPEK(byte[] baEncTrackData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            byte[] baTrackData = decrypt3DESCBC(baEncTrackData, baEncPINKey); // decrypt process run well with this function

            return baTrackData;
        } catch (Exception e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] decryptEMVDataWithIPEK(byte[] baEncEMVData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            byte[] baEMVData = decrypt3DESCBC(baEncEMVData, baEncPINKey); // decrypt process run well with this function

            return baEMVData;
        } catch (Exception e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] decryptDataWithIPEK(byte[] baEncEMVData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            byte[] baEMVData = decrypt3DESCBC(baEncEMVData, baEncPINKey); // decrypt process run well with this function

            return baEMVData;
        } catch (Exception e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] encryptEMVDataWithIPEK(byte[] baEMVData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            byte[] baEncEMVData = encrypt3DESCBC(baEMVData, baEncPINKey);

            return baEncEMVData;
        } catch (Exception e) {
            println("encryptEMVDataWithIPEK " + e.getMessage());
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] encryptTrackWithIPEK(byte[] baTrackData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            if (baDerivedKey == null) println("baDerivedKey " + "null");
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            if (baPINKey == null) println("baPINKey null");
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            if (baEncPINKey == null) println("baEncPINKey null");
            byte[] baEncTrackData = encrypt3DESCBC(baTrackData, baEncPINKey);
            if (baEncTrackData == null) println("baEncTrackData null");
            return baEncTrackData;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.flush();
            return null;
        }
    }

    public static byte[] encryptAmountWithIPEK(byte[] baAmountData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            if (baDerivedKey == null) println("baDerivedKey null");
            byte[] baPINKey = calculateDataEncryptionKey(baDerivedKey);
            if (baPINKey == null) println("baPINKey null");
            byte[] baEncPINKey = encrypt3DESECB(baPINKey, baPINKey);
            if (baEncPINKey == null) println("baEncPINKey null");
            byte[] baEncTrackData = encrypt3DESCBC(baAmountData, baEncPINKey);
            if (baEncTrackData == null) println("baEncTrackData null");

            return baEncTrackData;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] decryptPINBlockWithIPEK(byte[] baEncPINBlock, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            String hsDerivedKey = toHexString(baDerivedKey).toUpperCase();
            //System.out.println("hsDerivedKey: "+ hsDerivedKey);

            byte[] baPINKey = calculatePinEncryptionKey(baDerivedKey);
            String hsPINKey = toHexString(baPINKey).toUpperCase();
            //System.out.println("hsPINKey: "+ hsPINKey);

            byte[] baPINBlock = decrypt3DESCBC(baEncPINBlock, baPINKey);

            return baPINBlock;
        } catch (Exception e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] encryptPINBlockWithIPEK(byte[] baPINBlock, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            String hsDerivedKey = toHexString(baDerivedKey).toUpperCase();
            //System.out.println("hsDerivedKey: "+ hsDerivedKey);

            byte[] baPINKey = calculatePinEncryptionKey(baDerivedKey);
            String hsPINKey = toHexString(baPINKey).toUpperCase();
            //System.out.println("hsPINKey: "+ hsPINKey);

            byte[] baEncPINBlock = encrypt3DESCBC(baPINBlock, baPINKey);

            return baEncPINBlock;
        } catch (Exception e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
            System.out.flush();

            return null;
        }
    }

    public static byte[] decrypt3DESCBC(byte[] message, byte[] bkey) {
        try {

            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (RuntimeException | VerifyError | NoSuchMethodError |  NoClassDefFoundError e) {
            }
            SecretKey keySpec = new SecretKeySpec(bkey, "DESede");
            IvParameterSpec iv = new IvParameterSpec(new byte[8]);
            Cipher d_cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
            d_cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            byte[] cipherText = d_cipher.doFinal(message);

            return cipherText;
        } catch (Exception e) {
            //System.out.println(e.getMessage());
        }

        return null;
    }

    public static byte[] encrypt3DESCBC(byte[] message, byte[] bkey) {
        try {

            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (RuntimeException | VerifyError | NoSuchMethodError |  NoClassDefFoundError e) {
            }
            if (bkey == null) println("bKey2DES null");
            SecretKey keySpec = new SecretKeySpec(bkey, "DESede");

            IvParameterSpec iv = new IvParameterSpec(new byte[8]);

            Cipher e_cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
            e_cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            byte[] cipherText = e_cipher.doFinal(message);
            if (cipherText == null) println("cipherText null");

            return cipherText;
        } catch (Exception e) {
            //System.out.println(e.getMessage());
        }

        return null;
    }

    public static byte[] decrypt3DESECB(byte[] message, byte[] bkey) {
        try {

            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (RuntimeException | VerifyError | NoSuchMethodError |  NoClassDefFoundError e) {
            }
            SecretKey keySpec = new SecretKeySpec(bkey, "DESede");
            Cipher d_cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            d_cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] cipherText = d_cipher.doFinal(message);

            return cipherText;
        } catch (Exception e) {
            //System.out.println(e.getMessage());
        }

        return null;
    }

    public static byte[] encrypt3DESECB(byte[] message, byte[] bkey) {
        try {

            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (RuntimeException | VerifyError | NoSuchMethodError |  NoClassDefFoundError e) {
            }
            SecretKey keySpec = new SecretKeySpec(bkey, "DESede");
            Cipher e_cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            e_cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] cipherText = e_cipher.doFinal(message);
            return cipherText;
        } catch (Exception e) {
            //System.out.println(e.getMessage());
        }
        return null;
    }

    public static byte[] decryptWithIPEK(byte[] baData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baKey = calculateEncryptionKey(baDerivedKey);
            byte[] baEncKey = encrypt3DESECB(baKey, baKey);
            return decrypt3DESCBC(baData, baEncKey);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.flush();

            return null;
        }
    }

    public static byte[] encryptWithIPEK(byte[] baData, byte[] baKSN, byte[] baIPEK) {
        try {
            byte[] baDerivedKey = deriveKeyWithIPEK(baKSN, baIPEK);
            byte[] baKey = calculateEncryptionKey(baDerivedKey);
            byte[] baEncKey = encrypt3DESECB(baKey, baKey);

            return encrypt3DESCBC(baData, baEncKey);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.flush();

            return null;
        }
    }

    /**
     * @param derivedKey result of {@link #deriveKey(byte[], byte[])} to generate the key used to encrypt
     *                   card track info.
     * @return 16 byte array key that should be passed as the second parameter of {@link#trides_Decrypt(byte[], byte[])}
     */
    public static byte[] calculateEncryptionKey(byte[] derivedKey) {
        byte[] variant_constant = hexStringToBytes(PIN_ENCRYPTION_VARIANT_CONSTANT);
        byte[] derivedKeyL = ByteArrayUtil.subArray(derivedKey, 0, 7);
        byte[] derivedKeyR = ByteArrayUtil.subArray(derivedKey, 8, 15);

        // 1 - derivedKey_L XOR pin_variant_constant = pin_key_L
        byte[] pin_key_L = ByteArrayUtil.xor(derivedKeyL, variant_constant);

        // 2 - derivedKey_R XOR pin_variant_constant_R = pin_key_R
        byte[] pin_key_R = ByteArrayUtil.xor(derivedKeyR, variant_constant);

        return ByteArrayUtil.join(pin_key_L, pin_key_R);
    }

}
