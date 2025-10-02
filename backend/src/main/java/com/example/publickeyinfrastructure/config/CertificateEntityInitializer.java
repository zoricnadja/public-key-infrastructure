package com.example.publickeyinfrastructure.config;

import com.example.publickeyinfrastructure.model.CertificateEntity;
import org.springframework.stereotype.Component;

@Component
public class CertificateEntityInitializer {
    public CertificateEntityInitializer(SecurityProperties props) {
        CertificateEntity.setEncryptionPassphrase(
                props.getEncryption().getPassphrase()
        );
    }
}