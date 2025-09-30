package com.example.publickeyinfrastructure.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private final Keystore keystore = new Keystore();
    private final Encryption encryption = new Encryption();

    @Setter
    @Getter
    public static class Keystore {
        private String password;
    }

    @Setter
    @Getter
    public static class Encryption {
        private String passphrase;

    }
}
