package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.mapper.X500NameBuilder;
import com.example.publickeyinfrastructure.util.KeyUtil;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Entity;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "subjects")
public class Subject implements HasX500Fields{
    private static String encryptionKey = "ChangeThisEncryptionKeyToBeAtLeast32Chars!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    private String publicKeyAlgorithm;

    @Transient
    private PublicKey publicKey;

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        if (publicKey != null) {
            try {
                this.encryptedPublicKey = KeyUtil.encryptPublicKey(publicKey, encryptionKey);
                if (this.publicKeyAlgorithm == null) {
                    this.publicKeyAlgorithm = publicKey.getAlgorithm();
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to encrypt public key", e);
            }
        }
    }

    public PublicKey getPublicKey() {
        if (publicKey == null && encryptedPublicKey != null) {
            try {
                publicKey = KeyUtil.decryptPublicKey(encryptedPublicKey, encryptionKey, publicKeyAlgorithm);
            } catch (Exception e) {
                throw new RuntimeException("Failed to decrypt public key", e);
            }
        }
        return publicKey;
    }

    @Transient
    public X500Name getX500Name() {
        return X500NameBuilder.buildX500Name(this);
    }
}