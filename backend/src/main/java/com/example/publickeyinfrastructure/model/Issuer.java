package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.mapper.X500NameBuilder;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "issuers")
public class Issuer implements HasX500Fields{

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static String encryptionKey = "ChangeThisEncryptionKeyToBeAtLeast32Chars!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    @Column(name = "encrypted_public_key")
    private byte[] encryptedPublicKey;

    @Transient
    private PrivateKey privateKey;

    @Transient
    private PublicKey publicKey;

    @Column
    private String privateKeyAlgorithm;

    @Column
    private String publicKeyAlgorithm;

    @Column
    private String commonName;

    @Column
    private String organization;

    @Column
    private String organizationalUnit;

    @Column
    private String country;

    @Column
    private String state;

    @Column
    private String locality;

    @Column
    private String email;

    public PublicKey getPublicKey() {
        if (publicKey == null && encryptedPublicKey != null) {
            try {
                publicKey = decryptPublicKey(encryptedPublicKey);
            } catch (Exception e) {
                throw new RuntimeException("Failed to decrypt public key", e);
            }
        }
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        if (publicKey != null) {
            try {
                this.encryptedPublicKey = encryptPublicKey(publicKey);
                if (this.publicKeyAlgorithm == null) {
                    this.publicKeyAlgorithm = publicKey.getAlgorithm();
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to encrypt public key", e);
            }
        }
    }

    private byte[] encryptPublicKey(PublicKey publicKey) throws Exception {
        return encrypt(publicKey.getEncoded());
    }

    private PublicKey decryptPublicKey(byte[] encryptedKey) throws Exception {
        byte[] decryptedBytes = decrypt(encryptedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decryptedBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(publicKeyAlgorithm != null ? publicKeyAlgorithm : "RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private byte[] encrypt(byte[] data) throws Exception {
        if (encryptionKey == null || encryptionKey.length() < 32) {
            throw new IllegalStateException("Encryption key must be at least 32 characters long");
        }

        byte[] keyBytes = encryptionKey.substring(0,32).getBytes("UTF-8");
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

    private byte[] decrypt(byte[] encryptedData) throws Exception {
        if (encryptionKey == null || encryptionKey.length() < 32) {
            throw new IllegalStateException("Encryption key must be at least 32 characters long");
        }

        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Encrypted data is too short");
        }

        byte[] keyBytes = encryptionKey.substring(0,32).getBytes("UTF-8");
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

    @Transient
    public X500Name getX500Name() {
        return X500NameBuilder.buildX500Name(this);
    }
}