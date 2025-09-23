package com.example.publickeyinfrastructure.util;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyUtil {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    /**
     * Encrypt raw bytes using AES/GCM
     */
    public static byte[] encryptBytes(byte[] data, String encryptionKey) throws Exception {
        validateKey(encryptionKey);

        byte[] keyBytes = encryptionKey.substring(0, 32).getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encryptedData = cipher.doFinal(data);

        byte[] result = new byte[IV_LENGTH + encryptedData.length];
        System.arraycopy(iv, 0, result, 0, IV_LENGTH);
        System.arraycopy(encryptedData, 0, result, IV_LENGTH, encryptedData.length);

        return result;
    }

    /**
     * Decrypt raw bytes using AES/GCM
     */
    public static byte[] decryptBytes(byte[] encryptedData, String encryptionKey) throws Exception {
        validateKey(encryptionKey);

        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data is too short");
        }

        byte[] keyBytes = encryptionKey.substring(0, 32).getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, IV_LENGTH);

        byte[] cipherText = new byte[encryptedData.length - IV_LENGTH];
        System.arraycopy(encryptedData, IV_LENGTH, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        return cipher.doFinal(cipherText);
    }

    private static void validateKey(String encryptionKey) {
        if (encryptionKey == null || encryptionKey.length() < 32) {
            throw new IllegalStateException("Encryption key must be at least 32 characters long");
        }
    }

    /**
     * Convert PublicKey to AES-encrypted byte array
     */
    public static byte[] encryptPublicKey(PublicKey key, String encryptionKey) throws Exception {
        return encryptBytes(key.getEncoded(), encryptionKey);
    }

    /**
     * Decrypt AES-encrypted bytes into PublicKey
     */
    public static PublicKey decryptPublicKey(byte[] encryptedKey, String encryptionKey, String algorithm) throws Exception {
        byte[] decoded = decryptBytes(encryptedKey, encryptionKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm != null ? algorithm : "RSA");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * PublicKey <-> Base64 string
     */
    public static String publicKeyToBase64(PublicKey publicKey) {
        if (publicKey == null) return null;
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey base64ToPublicKey(String base64Key, String algorithm) throws Exception {
        if (base64Key == null) return null;
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance(algorithm != null ? algorithm : "RSA").generatePublic(spec);
    }
}

