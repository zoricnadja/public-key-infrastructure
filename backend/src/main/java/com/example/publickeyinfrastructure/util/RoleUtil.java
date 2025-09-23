package com.example.publickeyinfrastructure.util;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class RoleUtil {

    public static boolean hasAnyRole(Jwt jwt, String... rolesToCheck) {
        if (jwt == null) return false;

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess == null || !realmAccess.containsKey("roles")) {
            return false;
        }

        List<String> roles = (List<String>) realmAccess.get("roles");
        Set<String> rolesSet = Set.copyOf(roles);

        for (String role : rolesToCheck) {
            if (rolesSet.contains(role)) {
                return true;
            }
        }
        return false;
    }
}
