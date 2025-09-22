package com.example.publickeyinfrastructure.model;

import lombok.Getter;

@Getter
public enum UserRole {
    ADMIN("Administrator"),
    CA_USER("CA User"),
    REGULAR_USER("Regular User");

    private final String displayName;

    UserRole(String displayName) {
        this.displayName = displayName;
    }
}
