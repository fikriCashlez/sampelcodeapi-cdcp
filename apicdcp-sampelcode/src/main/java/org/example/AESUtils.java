package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

    public static byte[] decryptAES(byte[] key, byte[] iv, byte[] encrypted) {
        try {
            // Key must be 32 bytes for AES-256
            if (key.length != 32) {
                throw new IllegalArgumentException("Key must be 256 bits (32 bytes)");
            }

            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // PKCS5 = PKCS7 padding
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decrypted = cipher.doFinal(encrypted);

            System.out.println("Decrypted (Hex): " + bytesToHex(decrypted));
            System.out.println("Decrypted (ASCII): " + new String(decrypted));

            return decrypted;

        } catch (Exception e) {
            System.err.println("AES decryption failed: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Helper: byte[] to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}