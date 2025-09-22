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
import jakarta.persistence.Table;
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
import java.util.Date;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certificates")
public class Certificate {
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

    //todo save to db
    private byte[] publicKey;

    @Column
    private String publicKeyAlgorithm;

    public boolean isValid() {
        Date now = new Date();
        return issued.compareTo(now) <= 0 && expires.compareTo(now) > 0;
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
                SubjectPublicKeyInfo.getInstance(subject.getPublicKey())
        );

        // Napravi ContentSigner sa algoritmom i issuer privatnim ključem
        var signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .build(issuer.getPrivateKey());

        var holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);
    }
}
