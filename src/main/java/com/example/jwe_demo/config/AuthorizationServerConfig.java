package com.example.jwe_demo.config;

import com.example.jwe_demo.util.Generator;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Date;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    public JWKSource<SecurityContext> jwkSource () {
        RSAKey rsaKey = Generator.generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public ConfigurableJWTProcessor<SecurityContext> jwtProcessor() {
        return new DefaultJWTProcessor<>();
    }

    public String generateJweToken(RSAKey recipientKey) throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user")
                .issuer("auth-server")
                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000))
                .claim("sensitive_data", "This is sensitive information")
                .build();

        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(recipientKey.getKeyID())
                .build();

        JWEObject jweObject = new JWEObject(jweHeader, new Payload(claimsSet.toJSONObject()));
        jweObject.encrypt(new RSAEncrypter(recipientKey));

        return jweObject.serialize();
    }


 }
