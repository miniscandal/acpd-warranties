package com.authorizedcellphonedealer.acpdwarranties.services;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class AuthTokenService {
    RsaKeyLoader rsaKeyLoader;

    public AuthTokenService(RsaKeyLoader rsaKeyLoader) {
        this.rsaKeyLoader = rsaKeyLoader;
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }

    public boolean validateToken(HttpServletRequest request) throws Exception {
        String token = extractToken(request);
        if (token == null) {
            return false;
        }
        RSAPrivateKey rsaPrivateKey = rsaKeyLoader.loadPrivateKey("rsa-private-key.pem");
        RSAPublicKey rsaPublicKey = rsaKeyLoader.loadPublicKey("rsa-public-key.pem");

        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
            JWTVerifier verifier = JWT.require(algorithm).withIssuer("auth0").build();
            decodedJWT = verifier.verify(token);
            System.out.println("Descendants");
            return true;
        } catch (JWTVerificationException exception) {
            System.out.println(exception);
            return false;
        }

    }

    public void evie() throws Exception {
        RSAPrivateKey rsaPrivateKey = rsaKeyLoader.loadPrivateKey("rsa-private-key.pem");
        RSAPublicKey rsaPublicKey = rsaKeyLoader.loadPublicKey("rsa-public-key.pem");
        try {
            Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
            String token = JWT.create()
                    .withIssuer("auth0")
                    .sign(algorithm);
            System.out.println("");
            System.out.println(token);
            System.out.println("");
        } catch (JWTCreationException exception) {
        }
    }
}
