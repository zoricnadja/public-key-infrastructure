package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.util.KeyUtil;
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
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certificate_entities")
public class CertificateEntity {

    //todo
    private static String encryptionKey = "ChangeThisEncryptionKeyToBeAtLeast32Chars!aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String commonName;

    @Column
    private String surname;

    @Column
    private String givenName;

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

    @Transient
    private PrivateKey privateKey;

    @Transient
    private PublicKey publicKey;

    @Column
    private String privateKeyAlgorithm;

    @Column
    private String publicKeyAlgorithm;

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
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, commonName);
        builder.addRDN(BCStyle.SURNAME, surname);
        builder.addRDN(BCStyle.GIVENNAME, givenName);
        builder.addRDN(BCStyle.O, organization);
        builder.addRDN(BCStyle.OU, organizationalUnit);
        builder.addRDN(BCStyle.C, country);
        builder.addRDN(BCStyle.E, email);
        builder.addRDN(BCStyle.UID, String.valueOf(id));
        return builder.build();
    }
}