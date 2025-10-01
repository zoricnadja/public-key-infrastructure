package com.example.publickeyinfrastructure.util;

import com.example.publickeyinfrastructure.model.Role;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;


import java.util.List;
import java.util.stream.Collectors;

public class RoleUtil {
    public static List<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
    }

    public static boolean hasRole(Authentication authentication, Role role) {
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
