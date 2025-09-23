package com.example.publickeyinfrastructure.util;

import com.example.publickeyinfrastructure.model.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class RoleUtil {
    private static final Logger logger = LoggerFactory.getLogger(RoleUtil.class);

    public static List<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    public static boolean hasRole(Authentication authentication, Role role) {
        /*
        -----------------LOGOVANJE-----------------------
         */
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
        List<String> roleNames = roles.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        logger.debug(roleNames.toString());
        /*
        -------------------------------------------------
         */
        return getRoles(authentication).contains("ROLE_" + role);
    }

    public static Role extraxtRole(Authentication authentication) {
        Role role = null;
        if (RoleUtil.hasRole(authentication, Role.ADMIN)) {
            role = Role.ADMIN;
        }
        else if (RoleUtil.hasRole(authentication, Role.USER)) {
            role = Role.USER;
        }
        else if (RoleUtil.hasRole(authentication, Role.CA_USER)) {
            role = Role.CA_USER;
        }
        return role;
    }
}
