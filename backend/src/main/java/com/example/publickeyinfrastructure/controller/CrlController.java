package com.example.publickeyinfrastructure.controller;

import com.example.publickeyinfrastructure.service.CrlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/crl")
public class CrlController {

    private final CrlService crlService;

    @Autowired
    public CrlController(CrlService crlService) {
        this.crlService = crlService;
    }

    @GetMapping
    public ResponseEntity<byte[]> getCrl(@RequestParam String issuerDn) {
        try {
            byte[] crlBytes = crlService.generateCrlForIssuer(issuerDn);
            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("application/pkix-crl"))
                    .body(crlBytes);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(("CRL generation error: " + e.getMessage()).getBytes());
        }
    }
}
