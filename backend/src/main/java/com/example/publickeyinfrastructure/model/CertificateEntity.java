package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.util.KeyUtil;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certificate_entities")
public class CertificateEntity {
    private static final Logger logger = LoggerFactory.getLogger(CertificateEntity.class);

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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

    @Lob
    @Column
    private byte[] encryptedPublicKey;

    @Column
    private byte[] publicKeySalt;

    @Column
    private byte[] publicKeyIv;

    @Transient
    private PrivateKey privateKey;

    @Transient
    private PublicKey publicKey;

    @Column
    private String publicKeyAlgorithm;

    @Transient
    private static String encryptionPassphrase;

    public static void setEncryptionPassphrase(String passphrase) {
        if (passphrase == null || passphrase.length() < 12) {
            throw new IllegalArgumentException("Encryption passphrase must be at least 12 characters long");
        }
        encryptionPassphrase = passphrase;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        if (publicKey != null) {
            try {
                KeyUtil.EncryptionResult result = KeyUtil.encryptPublicKeyWithSaltIv(publicKey, encryptionPassphrase);
                this.encryptedPublicKey = result.encryptedData();
                this.publicKeySalt = result.salt();
                this.publicKeyIv = result.iv();

                if (this.publicKeyAlgorithm == null) {
                    this.publicKeyAlgorithm = publicKey.getAlgorithm();
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to encrypt public key", e);
            }
        }
    }

    public PublicKey getPublicKey() {
        if (publicKey == null && encryptedPublicKey != null && publicKeySalt != null && publicKeyIv != null) {
            try {
                publicKey = KeyUtil.decryptPublicKeyWithSaltIv(encryptedPublicKey, publicKeySalt, publicKeyIv, encryptionPassphrase, publicKeyAlgorithm);
            } catch (Exception e) {
                throw new RuntimeException("Failed to decrypt public key", e);
            }
        }
        return publicKey;
    }

    @Transient
    public X500Name getX500Name() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, commonName);
        builder.addRDN(BCStyle.O, organization);
        builder.addRDN(BCStyle.OU, organizationalUnit);
        builder.addRDN(BCStyle.C, country);
        builder.addRDN(BCStyle.E, email);
        builder.addRDN(BCStyle.UID, String.valueOf(id));
        builder.addRDN(BCStyle.ST, state);
        builder.addRDN(BCStyle.L, locality);

        return builder.build();
    }

    @Override
    public String toString() {
        return "CertificateEntity{" +
                "id=" + id +
                ", commonName='" + commonName + '\'' +
                ", organization='" + organization + '\'' +
                ", organizationalUnit='" + organizationalUnit + '\'' +
                ", country='" + country + '\'' +
                ", state='" + state + '\'' +
                ", locality='" + locality + '\'' +
                ", email='" + email + '\'' +
                ", encryptedPublicKey=" + Arrays.toString(encryptedPublicKey) +
                ", publicKeySalt=" + Arrays.toString(publicKeySalt) +
                ", publicKeyIv=" + Arrays.toString(publicKeyIv) +
                ", publicKeyAlgorithm='" + publicKeyAlgorithm + '\'' +
                '}';
    }
}
