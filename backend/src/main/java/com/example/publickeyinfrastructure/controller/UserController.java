package com.example.publickeyinfrastructure.controller;

import com.example.publickeyinfrastructure.dto.AssignCertificateRequest;
import com.example.publickeyinfrastructure.dto.UserResponse;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.service.UserService;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {
    private final UserService userService;
    private final ModelMapper modelMapper;
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    @Autowired
    public UserController(UserService userService, ModelMapper modelMapper) {
        this.userService = userService;
        this.modelMapper = modelMapper;
    }

    @GetMapping("/ca")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<List<UserResponse>> getCAUsers() {
        return ResponseEntity.ok(userService.findAllCAUsers().stream().map(user -> modelMapper.map(user, UserResponse.class)).toList());
    }

    @PutMapping("/assignment")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    public ResponseEntity<String> assign(@RequestBody AssignCertificateRequest request) {
        User user = this.userService.findById(request.getUserId());
        user.getCertificateSerialNumbers().add(request.getSerialNumber());
        this.userService.save(user);
        return ResponseEntity.ok("successfully assigned");
    }
}
