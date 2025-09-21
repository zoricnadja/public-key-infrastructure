package com.example.publickeyinfrastructure.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtUserFilter extends OncePerRequestFilter {

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            JwtAuthenticationToken token = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

            String email = String.valueOf(token.getTokenAttributes().get("email"));
            Optional<User> userOpt = this.userService.findByEmail(email);

            if (userOpt.isEmpty()) {
                String keycloakId = String.valueOf(token.getTokenAttributes().get("sub"));
                String firstName = String.valueOf(token.getTokenAttributes().get("given_name"));
                String lastName = String.valueOf(token.getTokenAttributes().get("family_name"));
                String organization = String.valueOf(token.getTokenAttributes().get("organization"));
                this.userService.save(new User(null, keycloakId, email, firstName, lastName, organization));
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to save user");
        }

        filterChain.doFilter(request, response);
    }

}
