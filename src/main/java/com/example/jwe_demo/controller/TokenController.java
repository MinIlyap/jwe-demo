package com.example.jwe_demo.controller;

import com.example.jwe_demo.config.AuthorizationServerConfig;
import com.example.jwe_demo.config.ResourceServerConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
public class TokenController {

    @Autowired
    private AuthorizationServerConfig authorizationServerConfig;

    @Autowired
    private ResourceServerConfig resourceServerConfig;

    @Autowired
    private RSAKey rsaKey;

    @PostMapping("/generate-token")
    public String generateToken() throws JOSEException {
        return authorizationServerConfig.generateJweToken(rsaKey);
    }

    @PostMapping("/validate-token")
    public String validatToken(@RequestBody String jweToken) {
        try {
            JWTClaimsSet claimsSet = resourceServerConfig.validateJweToken(jweToken);
            return "Token is valid. Claims: " + claimsSet.toJSONObject().toString();
        } catch (ParseException | JOSEException e) {
            return "Invalid token: " + e.getMessage();
        }
    }
}
