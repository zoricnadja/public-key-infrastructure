package com.example.publickeyinfrastructure.config;

public class Constants {
    public static final int ROOT_CERTIFICATE_DURATION = 10;
    public static final int INTERMEDIATE_CERTIFICATE_DURATION = 5;
    public static final int CERTIFICATE_DURATION = 1;
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final int KEY_SIZE = 4096;
    public static final char[] ENTRY_PASSWORD = "changeit".toCharArray();
}
