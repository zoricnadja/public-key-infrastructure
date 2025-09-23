package com.example.publickeyinfrastructure.model;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certificates")
public class Certificate {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static String encryptionKey = "ChangeThisEncryptionKeyToBeAtLeast32Chars!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "subject_id")
    private Subject subject;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private Issuer issuer;

    @Column(unique = true)
    private String serialNumber;

    @Column
    private Date issued;

    @Column
    private Date expires;

    @Enumerated(EnumType.STRING)
    @Column
    private CertificateType type;

    @Column
    private Boolean isWithdrawn;

    @Column
    private Integer version;

    @Column
    private String signatureAlgorithm;

    @Lob
    @Column
    private byte[] signature;

    @Lob
    @Column(name = "encrypted_public_key")
    private byte[] encryptedPublicKey;

    @Column
    private String publicKeyAlgorithm;

    @OneToMany(mappedBy = "certificate", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<CertificateExtension> extensions = new ArrayList<>();

    @Transient
    private PublicKey publicKey;

    public boolean isValid() {
        Date now = new Date();
        return issued.compareTo(now) <= 0 && expires.compareTo(now) > 0;
    }

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
    public X509Certificate toX509Certificate() throws Exception {
        X500Name subjectName = subject.getX500Name();
        X500Name issuerName = issuer.getX500Name();

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuerName,
                new BigInteger(serialNumber),
                issued,
                expires,
                subjectName,
                SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded()) // Koristi getter koji dekriptuje
        );

        var signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .build(issuer.getPrivateKey()); // Issuer učitava iz KeyStore-a

        var holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }

    @Override
    public String toString() {
        return "Certificate{" +
                "id=" + id +
                ", subject=" + subject +
                ", issuer=" + issuer +
                ", issued=" + issued +
                ", expires=" + expires +
                ", type=" + type +
                ", isWithdrawn=" + isWithdrawn +
                ", version=" + version +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", signature=" + Arrays.toString(signature) +
                ", publicKeyAlgorithm='" + publicKeyAlgorithm + '\'' +
                '}';
    }
}