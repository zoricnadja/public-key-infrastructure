package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.util.ExtensionUtil;
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
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
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

    private static final Logger logger = LoggerFactory.getLogger(Certificate.class);
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "subject_id")
    private CertificateEntity subject;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private CertificateEntity issuer;

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

    public void addExtension(CertificateExtension extension) {
        if (extensions == null) {
            extensions = new ArrayList<>();
        } else if (!(extensions instanceof ArrayList)) {
            extensions = new ArrayList<>(extensions);
        }
        extensions.add(extension);
    }

    public void removeExtension(CertificateExtension extension) {
        extensions.remove(extension);
    }

    public boolean isDateValid() {
        Date now = new Date();
        return issued.compareTo(now) <= 0 && expires.compareTo(now) > 0;
    }

    public X509Certificate toX509Certificate(PrivateKey issuerPrivateKey) throws Exception {
        X500Name subjectName = subject.getX500Name();
        logger.debug("Subject Name: " + subjectName.toString());
        X500Name issuerName = issuer.getX500Name();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                new BigInteger(serialNumber, 16),
                issued,
                expires,
                subjectName,
                subject.getPublicKey()
        );

        ExtensionUtil extensionUtil = new ExtensionUtil(issuer.getPublicKey(), subject.getPublicKey());

        for (CertificateExtension ext : extensions) {
            extensionUtil.addExtension(certBuilder, ext.getExtensionType().getOid(), ext.getIsCritical(), ext.getValue());
        }

        ContentSigner signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                .setProvider(Constants.PROVIDER)
                .build(issuerPrivateKey);

        String crlUrl = "http://localhost:8080/crl?issuerDn=" + URLEncoder.encode(subjectName.toString(), StandardCharsets.UTF_8);
        DistributionPointName distPointName = new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))
        );
        DistributionPoint[] distPoints = new DistributionPoint[] {
                new DistributionPoint(distPointName, null, null)
        };
        certBuilder.addExtension(
                Extension.cRLDistributionPoints,
                false,
                new CRLDistPoint(distPoints)
        );

        X509CertificateHolder holder = certBuilder.build(signer);

        return new JcaX509CertificateConverter()
                .setProvider(Constants.PROVIDER)
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