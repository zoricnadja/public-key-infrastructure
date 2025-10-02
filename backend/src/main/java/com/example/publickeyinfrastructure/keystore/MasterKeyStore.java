package com.example.publickeyinfrastructure.keystore;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.config.SecurityProperties;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;

@Getter
@Component
public class MasterKeyStore {
    private static final Logger logger = LoggerFactory.getLogger(MasterKeyStore.class);
    @Value("${master.keystore.path}")
    private String masterKeystorePath;
    private final SecurityProperties securityProperties;
    private SecretKey masterKey;

    public MasterKeyStore(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @PostConstruct
    public void init() {
        try {
            File ksFile = new File(masterKeystorePath);
            if (ksFile.exists()) {
                loadMasterKey(ksFile);
            } else {
                generateMasterKey(ksFile);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize master keystore", e);
        }
    }

    private void generateMasterKey(File ksFile) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        masterKey = keyGen.generateKey();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, securityProperties.getEncryption().getPassphrase().toCharArray());
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(masterKey);
        keyStore.setEntry(Constants.MASTER_KEY_ALIAS, entry, new KeyStore.PasswordProtection(securityProperties.getEncryption().getPassphrase().toCharArray()));

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            keyStore.store(fos, securityProperties.getEncryption().getPassphrase().toCharArray());
        }
        logger.debug("Master key generated and stored. {}", masterKey);
    }

    private void loadMasterKey(File ksFile) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksFile)) {
            keyStore.load(fis, securityProperties.getEncryption().getPassphrase().toCharArray());
        }
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(Constants.MASTER_KEY_ALIAS,
                new KeyStore.PasswordProtection(securityProperties.getEncryption().getPassphrase().toCharArray()));
        masterKey = entry.getSecretKey();
        logger.debug("Master key loaded from keystore.{}", masterKey);
    }

}
