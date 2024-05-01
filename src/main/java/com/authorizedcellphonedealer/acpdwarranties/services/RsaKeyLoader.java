package com.authorizedcellphonedealer.acpdwarranties.services;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Service;

@Service
public class RsaKeyLoader {
    private String readFile(final String fileName) throws IOException {
        final String pathName = getClass().getClassLoader().getResource(fileName).getFile();
        final File file = new File(pathName);

        final Path path = file.toPath();
        return new String(Files.readAllBytes(path));
    }

    public RSAPrivateKey loadPrivateKey(String file) throws Exception {
        String pemString = readFile(file);
        String privateKeyPEM = pemString
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        return rsaPrivateKey;
    }

    public RSAPublicKey loadPublicKey(String file) throws Exception {
        String pemString = readFile(file);
        String publicKeyPEM = pemString
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

        return rsaPublicKey;
    }
}
