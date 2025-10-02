package com.example.publickeyinfrastructure.keystore;

import com.example.publickeyinfrastructure.config.SecurityProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Component
public class OrganizationKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(OrganizationKeyStore.class);
    private static final int GCM_TAG_LENGTH = 128;
    @Value("${organization.keystore.path}")
    private String organizationKeystorePath;
    private final MasterKeyStore masterKeyStore;
    private final SecurityProperties securityProperties;

    private KeyStore keyStore;

    public OrganizationKeyStore(MasterKeyStore masterKeyStore, SecurityProperties securityProperties) {
        this.masterKeyStore = masterKeyStore;
        this.securityProperties = securityProperties;
    }

    @PostConstruct
    public void init() {
        try {
            File ksFile = new File(organizationKeystorePath);
            keyStore = KeyStore.getInstance("PKCS12");

            if (ksFile.exists()) {
                try (FileInputStream fis = new FileInputStream(ksFile)) {
                    keyStore.load(fis, securityProperties.getKeystore().getPassword().toCharArray());
                    logger.debug("Loaded organization keystore");
                }
            } else {
                keyStore.load(null, securityProperties.getKeystore().getPassword().toCharArray());
                saveKeystore();
                logger.debug("Created new organization keystore");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize OrganizationKeyStore", e);
        }
    }

    public void storeOrganizationKey(String orgId, String keyId, PrivateKey privateKey) throws Exception {
        SecretKey masterKey = masterKeyStore.getMasterKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec);

        byte[] encrypted = cipher.doFinal(privateKey.getEncoded());

        String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);

        EncryptedKeyData keyData = new EncryptedKeyData(encryptedBase64, ivBase64);

        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(
                new javax.crypto.spec.SecretKeySpec(serializeKeyData(keyData), "AES")
        );

        keyStore.setEntry(orgId + "-" + keyId, entry,
                new KeyStore.PasswordProtection(securityProperties.getKeystore().getPassword().toCharArray()));

        saveKeystore();

    }

    private byte[] serializeKeyData(EncryptedKeyData keyData) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(keyData);
            return baos.toByteArray();
        }
    }

    public PrivateKey loadOrganizationKey(String orgId, String keyId) throws Exception {
        String alias = orgId + "-" + keyId;

        if (!keyStore.containsAlias(alias)) {
            logger.error("Alias '{}' not found", alias);
            return null;
        }

        SecretKey encryptedKeyEntry = (SecretKey) keyStore.getKey(alias, securityProperties.getKeystore().getPassword().toCharArray());
        EncryptedKeyData keyData = deserializeKeyData(encryptedKeyEntry.getEncoded());

        byte[] encrypted = Base64.getDecoder().decode(keyData.getEncryptedKeyBase64());
        byte[] iv = Base64.getDecoder().decode(keyData.getIvBase64());
        SecretKey masterKey = masterKeyStore.getMasterKey();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] decrypted = cipher.doFinal(encrypted);

        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decrypted));
    }

    private EncryptedKeyData deserializeKeyData(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (EncryptedKeyData) ois.readObject();
        }
    }

    private void saveKeystore() {
        try (FileOutputStream fos = new FileOutputStream(organizationKeystorePath)) {
            keyStore.store(fos, securityProperties.getKeystore().getPassword().toCharArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to save OrganizationKeyStore", e);
        }
    }
}
