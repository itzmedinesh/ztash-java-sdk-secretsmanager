package org.microcrafts.secretsmanager.core;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.microcrafts.openziti.ldap.ZitiApp;
import org.microcrafts.openziti.ldap.ZitiLdapConnectionConfig;
import org.microcrafts.secretsmanager.utils.SecretsManagerException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.microcrafts.secretsmanager.utils.SecretsManagerUtils.*;

@Slf4j
public class SecretsManagerInitializer {

    private final String tokenFilePath;
    private final String tokenFileName;

    public SecretsManagerInitializer(String tokenFilePath, String tokenFileName) {
        this.tokenFilePath = tokenFilePath;
        this.tokenFileName = tokenFileName;
    }

    public SecretsManagerContext getContext() throws SecretsManagerException {

        validateTokenFilePath(tokenFilePath);

        KeyStore keystore = initKeyStore();

        File keyFile = new File(tokenFilePath + File.separator + getKeyFileName());

        SecretRepositoryCredentials secretRepositoryCredentials;

        if (keyFile.exists()) {
            log.info("Reading zecrets access parameters from existing key store");
            secretRepositoryCredentials = getSecretAccessCreds(keystore, keyFile);
        } else {
            log.info("Creating new key store to store and read zecrets access parameters");
            secretRepositoryCredentials = setSecretAccessCreds(keystore, keyFile, getClaims(
                validateGetToken(new File(tokenFilePath + File.separator + tokenFileName))));
        }

        try {
            return SecretsManagerContext.builder()
                .secretRepositoryCredentials(secretRepositoryCredentials)
                .secretRepoServiceContext(new ZitiApp.CredentialBuilder().fromKey(
                    secretRepositoryCredentials.getSecretAccessIdentity()).build().getContext())
                .secretRepoConnectionConfig(
                    new ZitiLdapConnectionConfig.Builder().service(secretRepoService())
                        .bindDn(secretRepoConnectDn(secretRepositoryCredentials))
                        .bindPass(secretRepositoryCredentials.getSecretAccessKey()).build())
                .build();

        } catch (Exception e) {
            throw new SecretsManagerException(
                "Unable to initialize zecrets manager; Reason: ztash context initialization failed");
        }

    }

    @NotNull private KeyStore initKeyStore() {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(getKeyFileType());
        } catch (KeyStoreException e) {
            throw new IllegalArgumentException(
                String.format("Keystore format : %s not supported", "PKCS12"), e);
        }
        return keystore;
    }


    private SecretRepositoryCredentials setSecretAccessCreds(KeyStore keystore, File keyFile,
        Claims claims) {
        try {
            String zecretAccessKeyId = claims.get("zecretAccessKeyId", String.class);
            String zecretAccessKey = claims.get("zecretAccessKey", String.class);
            String zecretAccessToken = claims.get("zecretAccessToken", String.class);

            String secretAccessIdentity = ZitiApp.enroll(
                new ByteArrayInputStream(zecretAccessToken.getBytes(StandardCharsets.UTF_8)));

            keystore.load(null);

            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBE");

            keystore.setEntry("secret-access-key-id", new KeyStore.SecretKeyEntry(
                    secretKeyFactory.generateSecret(new PBEKeySpec(zecretAccessKeyId.toCharArray()))),
                new KeyStore.PasswordProtection("password".toCharArray()));

            keystore.setEntry("secret-access-key", new KeyStore.SecretKeyEntry(
                    secretKeyFactory.generateSecret(new PBEKeySpec(zecretAccessKey.toCharArray()))),
                new KeyStore.PasswordProtection("password".toCharArray()));

            keystore.setEntry("secret-access-identity", new KeyStore.SecretKeyEntry(
                    secretKeyFactory.generateSecret(
                        new PBEKeySpec(secretAccessIdentity.toCharArray()))),
                new KeyStore.PasswordProtection("password".toCharArray()));

            keystore.store(new FileOutputStream(keyFile), "password".toCharArray());

            return SecretRepositoryCredentials.builder().secretAccessKeyId(zecretAccessKeyId)
                .secretAccessKey(zecretAccessKey).secretAccessIdentity(secretAccessIdentity)
                .build();

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(
                String.format("Keystore : %s loading (or) entries reading error", keyFile), e);
        }
    }

    private SecretRepositoryCredentials getSecretAccessCreds(KeyStore keystore, File keyFile) {
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBE");

            keystore.load(new FileInputStream(keyFile), getKeyFileAccess());

            KeyStore.SecretKeyEntry secretAccessKeyId =
                (KeyStore.SecretKeyEntry) keystore.getEntry("secret-access-key-id",
                    new KeyStore.PasswordProtection(getKeyFileAccess()));

            PBEKeySpec secretAccessKeyIdSpec =
                (PBEKeySpec) secretKeyFactory.getKeySpec(secretAccessKeyId.getSecretKey(),
                    PBEKeySpec.class);

            String secretKeyKeyIdStr = new String(secretAccessKeyIdSpec.getPassword());

            KeyStore.SecretKeyEntry secretAccessKey =
                (KeyStore.SecretKeyEntry) keystore.getEntry("secret-access-key",
                    new KeyStore.PasswordProtection(getKeyFileAccess()));

            PBEKeySpec secretAccessKeySpec =
                (PBEKeySpec) secretKeyFactory.getKeySpec(secretAccessKey.getSecretKey(),
                    PBEKeySpec.class);

            String secretAccessKeyStr = new String(secretAccessKeySpec.getPassword());

            KeyStore.SecretKeyEntry secretAccessIdentity =
                (KeyStore.SecretKeyEntry) keystore.getEntry("secret-access-identity",
                    new KeyStore.PasswordProtection(getKeyFileAccess()));

            PBEKeySpec secretAccessIdentitySpec =
                (PBEKeySpec) secretKeyFactory.getKeySpec(secretAccessIdentity.getSecretKey(),
                    PBEKeySpec.class);

            String secretAccessIdentityStr = new String(secretAccessIdentitySpec.getPassword());

            return SecretRepositoryCredentials.builder().secretAccessKeyId(secretKeyKeyIdStr)
                .secretAccessKey(secretAccessKeyStr).secretAccessIdentity(secretAccessIdentityStr)
                .build();

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableEntryException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(
                String.format("Keystore : %s loading (or) entries reading error", keyFile), e);
        }
    }

    private Claims getClaims(String jwtString) {
        Jws<Claims> jwt = Jwts.parserBuilder().setSigningKey(new SecretKeySpec(Base64.getDecoder()
            .decode(
                "KkYtSmFOZFJnVWtYcDJzNXY4eS9CP0QoRytLYlBlU2hWbVlxM3Q2dzl6JEMmRilIQE1jUWZUalduWnI0dTd4IQ=="),
            SignatureAlgorithm.HS256.getJcaName())).build().parseClaimsJws(jwtString);
        return jwt.getBody();
    }

    private String validateGetToken(File tokenFile) {
        if (!tokenFile.exists())
            throw new IllegalArgumentException(
                String.format("Token file : %s does not exist", tokenFile));

        if (!tokenFile.canRead())
            throw new IllegalArgumentException(
                String.format("Token file : %s should hava read permission", tokenFile));

        String jwtString;

        try {
            jwtString = Files.readString(tokenFile.toPath());
        } catch (IOException e) {
            throw new IllegalArgumentException(
                String.format("Token file : %s could not be read", tokenFile), e);
        }

        return jwtString;
    }

    private void validateTokenFilePath(String tokenFilePath) {
        File tokenFileDir = new File(tokenFilePath);

        if (!tokenFileDir.exists())
            throw new IllegalArgumentException(
                String.format("Token file path : %s does not exist", tokenFilePath));

        if (!tokenFileDir.isDirectory())
            throw new IllegalArgumentException(
                String.format("Token file path : %s is not a directory", tokenFilePath));

        if (!tokenFileDir.canWrite())
            throw new IllegalArgumentException(
                String.format("Token file path : %s should hava write permission", tokenFilePath));
    }

}
