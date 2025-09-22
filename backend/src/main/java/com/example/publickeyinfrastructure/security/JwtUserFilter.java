package com.example.publickeyinfrastructure.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.publickeyinfrastructure.model.Role;
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
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/actuator") || path.startsWith("/public");
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();

            String email = jwt.getClaim("email");
            Optional<User> userOpt = this.userService.findByEmail(email);

            if (userOpt.isEmpty()) {
                List<String> roles = extractRoles(jwt);
                Role role = roles.stream()
                        .map(Role::fromString)
                        .filter(opt -> opt.isPresent())
                        .map(opt -> opt.get())
                        .findFirst()
                        .orElse(Role.USER);

                String keycloakId = jwt.getClaim("sub");
                String firstName = jwt.getClaim("given_name");
                String lastName = jwt.getClaim("family_name");
                String organization = jwt.getClaim("organization");
                this.userService.save(new User(null, keycloakId, email, firstName, lastName, organization, role));
            }
        }

        filterChain.doFilter(request, response);
    }

    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = new ArrayList<>();

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            roles.addAll((Collection<String>) realmAccess.get("roles"));
        }

        return roles;
    }

}
