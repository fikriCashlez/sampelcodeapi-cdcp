package org.example;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.example.Main.bytesToHex;


public class RSAUtil {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String KEY_PROVIDER = "BC";

    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    protected static final int KEY_SIZE = 2048;

    public static Map<String, Object> initKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    public static String getPrivateKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());
    }

    public static String getPublicKey(Map<String, Object> keyMap) {
        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return encryptBASE64(key.getEncoded());
    }

    public static String decryptByPrivateKey(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] keyBytes = decryptBASE64(key);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] baDecResultMsg = cipher.doFinal(data);
        return bytesToHex(baDecResultMsg);
    }

    public static byte[] decryptByPublicKey(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] keyBytes = decryptBASE64(key);

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    public static byte[] encryptByPublicKey(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] keyBytes = decryptBASE64(key);

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }


    public static byte[] encryptByPrivateKey(byte[] data, String key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[] keyBytes = decryptBASE64(key);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    public static String sign(byte[] data, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        byte[] keyBytes = decryptBASE64(privateKey);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }


    public static boolean verify(byte[] data, String publicKey, String sign) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {

        byte[] keyBytes = decryptBASE64(publicKey);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        return signature.verify(decryptBASE64(sign));
    }

    public static PublicKey getPublicKey(String MODULUS, String EXPONENT) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] modulusBytes = Base64.getDecoder().decode(MODULUS);
        byte[] exponentBytes = Base64.getDecoder().decode(EXPONENT);

        BigInteger modulus = new BigInteger(1, (modulusBytes));
        BigInteger exponent = new BigInteger(1, (exponentBytes));

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory kf = KeyFactory.getInstance(RSAUtil.KEY_ALGORITHM);
        return kf.generatePublic(spec);
    }

    public static String encryptBASE64(byte[] key) {
        return Base64.getEncoder().encodeToString(key);
    }

    public static byte[] decryptBASE64(String key) {
        return Base64.getDecoder().decode(key);
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(KEY_SIZE);

        KeyPair keyPair = generator.generateKeyPair();

        return keyPair;
    }
}
