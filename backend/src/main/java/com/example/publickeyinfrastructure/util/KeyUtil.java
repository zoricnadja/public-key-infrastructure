package com.example.publickeyinfrastructure.util;

import com.example.publickeyinfrastructure.config.Constants;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class KeyUtil {

    public static final int SALT_LENGTH = 16;
    public static final int IV_LENGTH = 12;
    public static final int TAG_LENGTH_BITS = 128;
    public static final int PBKDF2_ITERATIONS = 65536;
    public static final int KEY_LENGTH_BITS = 256;

    public record EncryptionResult(byte[] encryptedData, byte[] salt, byte[] iv) {
    }

    public static EncryptionResult encryptPublicKeyWithSaltIv(PublicKey key, String passphrase) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKeySpec secretKey = deriveKey(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] encrypted = cipher.doFinal(key.getEncoded());

        return new EncryptionResult(encrypted, salt, iv);
    }

    public static PublicKey decryptPublicKeyWithSaltIv(byte[] encryptedData, byte[] salt, byte[] iv, String passphrase, String algorithm) throws Exception {
        SecretKeySpec secretKey = deriveKey(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] decrypted = cipher.doFinal(encryptedData);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decrypted);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    private static SecretKeySpec deriveKey(String passphrase, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String publicKeyToBase64(PublicKey publicKey) {
        if (publicKey == null) return null;
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey base64ToPublicKey(String base64Key, String algorithm) throws Exception {
        if (base64Key == null) return null;
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance(algorithm != null ? algorithm : Constants.KEY_ALGORITHM).generatePublic(spec);
    }
}

