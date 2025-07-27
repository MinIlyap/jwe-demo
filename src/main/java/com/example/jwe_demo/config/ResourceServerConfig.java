package com.example.jwe_demo.config;

import com.example.jwe_demo.util.Generator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.text.ParseException;

@Configuration
public class ResourceServerConfig {
    private final RSAKey rsaKey;

    public ResourceServerConfig() {
        this.rsaKey = Generator.generateRsaKey();
    }

    @Bean
    public RSAKey rsaKey() {
        return this.rsaKey;
    }

    public JWTClaimsSet validateJweToken(String jweToken) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(jweToken);
        jweObject.decrypt(new RSADecrypter(rsaKey));

        return JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());
    }
}
