package com.example.publickeyinfrastructure.dto;

import com.example.publickeyinfrastructure.model.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private Integer id;
    private String keycloakId;
    private String email;
    private String firstName;
    private String lastName;
    private String organization;
    private Role role;
    private List<String> certificateSerialNumbers;
}
