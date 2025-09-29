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
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
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

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "subject_id")
    private CertificateEntity subject;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private CertificateEntity issuer;

    //todo pseudo random niz brojeva
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

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "certificate_id")
    private List<CertificateExtension> extensions = new ArrayList<>();

    //todo do i need this?
    public void addExtension(CertificateExtension extension) {
        extensions.add(extension);
    }

    public void removeExtension(CertificateExtension extension) {
        extensions.remove(extension);
    }

    public boolean isDateValid() {
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
                SubjectPublicKeyInfo.getInstance(subject.getPublicKey().getEncoded())
        );

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider("BC")
                .build(issuer.getPrivateKey());

        X509CertificateHolder holder = certBuilder.build(signer);

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
                '}';
    }
}