package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.util.KeyUtil;
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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
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
    @Column
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