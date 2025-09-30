package com.example.publickeyinfrastructure.config;

public class Constants {
    public static final int ROOT_CERTIFICATE_DURATION = 10;
    public static final int INTERMEDIATE_CERTIFICATE_DURATION = 5;
    public static final int CERTIFICATE_DURATION = 1;
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String CRYPTO_ALGORITHM = "AES";
    public static final String KEY_ALGORITHM = "RSA";
    public static final String CRYPTO_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String RANDOM_ALGORITHM = "SHA1PRNG";
    public static final String RANDOM_PROVIDER = "SUN";
    public static final String PROVIDER = "BC";
    public static final int KEY_SIZE = 2048;
    public static final char[] ENTRY_PASSWORD = "changeit".toCharArray();
}
