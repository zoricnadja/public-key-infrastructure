package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.Issuer;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.CertificateRepository;
import com.example.publickeyinfrastructure.repository.IssuerRepository;
import com.example.publickeyinfrastructure.repository.UserRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

@Service
public class CertificateService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private IssuerRepository issuerRepository;

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<Issuer> getIssuers() {
        return issuerRepository.findAll();
    }

//    public List<Certificate> getAvailableCACertificates(User user, CertificateType requestedType) {
//        switch (user.getRole()) {
//            case ADMIN:
//                return getCAForRootAdmin(requestedType);
//            case CA_USER:
//                return getCAForCAUser(user, requestedType);
//            case REGULAR_USER:
//                return getCAForRegularUser(user, requestedType);
//            default:
//                return List.of();
//        }
//    }

    /**
     * Root CA Admin može koristiti sve validne CA sertifikate
     */
//    private List<Certificate> getCAForRootAdmin(CertificateType requestedType) {
//        // Direktno iz baze - već filtrirani validni sertifikati
//        return certificateRepository.findAllValidCACertificates();
//    }

    /**
     * CA korisnik može koristiti samo CA sertifikate iz svog lanca i svoje organizacije
     */
//    private List<Certificate> getCAForCAUser(User user, CertificateType requestedType) {
//        // Direktno iz baze sa filterom organizacije - već validni sertifikati
//        List<Certificate> validCAs = certificateRepository.findValidCAByOrganization(
//                user.getOrganization()
//        );
//
//        // Za intermediate i end-entity sertifikate, korisnik može koristiti
//        // bilo koji CA iz svog lanca (Root ili Intermediate) - već je filtrirano u query-ju
//        if (requestedType == CertificateType.INTERMEDIATE_CA ||
//                requestedType == CertificateType.END_ENTITY) {
//            return validCAs;
//        }
//
//        return validCAs;
//    }
//
//    /**
//     * Običan korisnik može birati iz dostupnih CA sertifikata
//     * (moguce ogranicenje po organizaciji ili javni CA)
//     */
//    private List<Certificate> getCAForRegularUser(User user, CertificateType requestedType) {
//        // Običan korisnik može da zatraži samo End-Entity sertifikat
//        if (requestedType != CertificateType.END_ENTITY) {
//            return List.of(); // Nema dozvolu za CA sertifikate
//        }
//
//        // Direktno iz baze - kombinuje organizacione i javne CA, već validne
//        return certificateRepository.findValidCAForRegularUser(user.getOrganization());
//    }

    /**
     * Alternativno - koristi universalnu metodu sa parametrima
     */
    public List<Certificate> getCACertificates(User user) {
        List<CertificateType> allowedTypes = List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE);

        return switch (user.getRole()) {
            case ADMIN ->
                // Root admin može koristiti sve validne CA sertifikate
                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, null);
            case CA_USER ->
                // CA korisnik samo iz svoje organizacije
                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, user.getOrganization());
            case REGULAR_USER ->
                // Običan korisnik samo za End-Entity (koristi custom query)
                    certificateRepository.findValidCAForRegularUser(user.getOrganization());
            default -> List.of();
        };
    }

    /**
     * Provera digitalnog potpisa sertifikata
     */
//    public boolean checkCertificateChain(Certificate cert) {
//        try {
//            if (cert == null || cert.getIssuer() == null) {
//                return false;
//            }
//
//            X509Certificate certHolder = cert.toX509Certificate();
//
//            PublicKey issuerPublicKey = cert.getIssuer().getPublicKey();
//            if (issuerPublicKey == null) return false;
//
//            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
//                    .build(issuerPublicKey);
//            if (!certHolder.isSignatureValid(verifier)) {
//                return false;
//            }
//
//            if (cert.getType() == CertificateType.ROOT) {
//                return cert.getSubject().getX500Name().equals(cert.getIssuer().getX500Name());
//            }
//
//            Certificate issuerCert = certificateRepository.findBySubject(cert.getIssuer());
//            if (issuerCert == null) return false;
//
//            return checkCertificateChain(issuerCert);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            return false;
//        }
//    }

    public boolean checkChain(Certificate certificate) {
        try {
            X500Name subjectName = certificate.getSubject().getX500Name();
            X500Name issuerName = certificate.getIssuer().getX500Name();

            if (certificate.getType() == CertificateType.ROOT && subjectName.equals(issuerName)) {
                certificate.toX509Certificate().verify(certificate.getIssuer().getPublicKey());
                return true;
            }

            Optional<Certificate> parentOpt = certificateRepository.findBySubject_CommonName(issuerName.toString());
            if (parentOpt.isEmpty()) return false;

            Certificate parent = parentOpt.get();
            X509Certificate parentCert = parent.toX509Certificate();

            if (parent.isValid()) return false;

            if (Boolean.TRUE.equals(parent.getIsWithdrawn())) return false;

            parentCert.verify(parent.getIssuer().getPublicKey());

            return checkChain(parent);

        } catch (Exception e) {
            return false;
        }
    }


//    public Certificate createCertificate(Certificate certificateRequest) {
//        Subject subject = generateSubjectData(certificateRequest);
//        Issuer issuer;
//        if (certificateRequest.getIssuer() != null)
//            issuer = generateIssuer(certificateRequest);
//        else {
//            issuer = new Issuer(subject.getX500Name(), subject.getPrivateKey());
//        }
//
//        X509Certificate xCertificate = generateCertificate(issuer, subject);
//
//        Certificate certificateEntity = new Certificate(xCertificate, certificateRequest);
//        certificateEntity = certificateRepository.save(certificateEntity);
//
//        return certificateEntity;
//    }
//
//    private X509Certificate generateCertificate(Issuer issuer, Subject subject) throws CertificateException, OperatorCreationException {
//        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
//        builder = builder.setProvider("BC");
//
//        // Formira se objekat koji ce sadrzati privatni kljuc i koji ce se koristiti za potpisivanje sertifikata
//        ContentSigner contentSigner = builder.build(issuer.getPrivateKey());
//
//        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
//                issuer.getX500name(),
//                new BigInteger(subject.getSerialNumber()),
//                subject.getStartDate(),
//                subject.getEndDate(),
//                subject.getX500name(),
//                subject.getPublicKey());
//        X509CertificateHolder certHolder = certGen.build(contentSigner);
//        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
//        certConverter = certConverter.setProvider("BC");
//
//        // Konvertuje objekat u sertifikat
//        return certConverter.getCertificate(certHolder);
//    }
//
//    private String generateAlias(User user){
//        return String.valueOf(new Random().nextLong());
//    }

//    private Subject generateSubject(Certificate certificateRequest){
//        KeyPair keyPairSubject = generateKeyPair();
//        User user = certificateRequest.getSubject();
//
//        DateUtil dateUtil = new DateUtil();
//        Date startDate = dateUtil.generateStartTime();
//        Date endDate = dateUtil.generateEndTime(startDate, certificateRequest);
//        String serialNumber = generateAlias(certificateRequest.getSubject());
//
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.CN, user.getUsername());
//        builder.addRDN(BCStyle.SURNAME, user.getSurname());
//        builder.addRDN(BCStyle.GIVENNAME, user.getName());
//        builder.addRDN(BCStyle.E, user.getEmail());
//        builder.addRDN(BCStyle.UID, user.getId().toString());
//
//        return new Subject(keyPairSubject.getPublic(), keyPairSubject.getPrivate(), builder.build(), serialNumber,
//                startDate, endDate);
//    }
//
//    private Issuer generateIssuer(CertificateRequest certificateRequest){
//        User issuer = certificateRepository.findById(certificateRequest.getIssuer().getId()).get().getSubject();
//        PrivateKey issuerKey = KeyStoreReader.readPrivateKey(certificateRequest.getIssuer().getSerialNumber(), KeyStoreConstants.ENTRY_PASSWORD);
//        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
//        builder.addRDN(BCStyle.CN, issuer.getUsername());
//        builder.addRDN(BCStyle.SURNAME, issuer.getSurname());
//        builder.addRDN(BCStyle.GIVENNAME, issuer.getName());
//        builder.addRDN(BCStyle.E, issuer.getEmail());
//        builder.addRDN(BCStyle.UID, String.valueOf(issuer.getId()));
//
//        return new Issuer(builder.build(), issuerKey);
//    }
}
