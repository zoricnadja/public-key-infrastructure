package com.example.publickeyinfrastructure.model;

import java.util.Optional;

public enum Role {
    USER,
    CA_USER,
    ADMIN;

    public static Optional<Role> fromString(String role) {
        if (role == null) return Optional.empty();
        try {
            return Optional.of(Role.valueOf(role.toUpperCase().replace("-", "_")));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
