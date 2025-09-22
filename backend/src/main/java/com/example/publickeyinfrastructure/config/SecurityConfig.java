package com.example.publickeyinfrastructure.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.example.publickeyinfrastructure.security.JwtUserFilter;
import com.example.publickeyinfrastructure.security.KeycloakRoleConverter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private KeycloakRoleConverter keycloakRoleConverter;
    private JwtUserFilter jwtUserFilter;

    @Autowired
    public SecurityConfig(KeycloakRoleConverter keycloakRoleConverter, JwtUserFilter jwtUserFilter) {
        this.keycloakRoleConverter = keycloakRoleConverter;
        this.jwtUserFilter = jwtUserFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/public/**").permitAll() // TODO: Adjust public endpoints
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakRoleConverter))
            )
            .addFilterBefore(jwtUserFilter, BasicAuthenticationFilter.class);
        return http.build();
    }
}
