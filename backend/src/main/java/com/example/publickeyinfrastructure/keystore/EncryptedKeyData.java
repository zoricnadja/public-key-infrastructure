package com.example.publickeyinfrastructure.keystore;

import lombok.Getter;

import java.io.Serializable;

@Getter
public class EncryptedKeyData implements Serializable {
    private final String encryptedKeyBase64;
    private final String ivBase64;

    public EncryptedKeyData(String encryptedKeyBase64, String ivBase64) {
        this.encryptedKeyBase64 = encryptedKeyBase64;
        this.ivBase64 = ivBase64;
    }

}
