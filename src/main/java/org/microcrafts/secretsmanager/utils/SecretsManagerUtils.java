package org.microcrafts.secretsmanager.utils;

import org.jetbrains.annotations.NotNull;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchResponse;
import org.microcrafts.secretsmanager.domain.Secret;
import org.microcrafts.secretsmanager.core.SecretRepositoryCredentials;

import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class SecretsManagerUtils {

    @NotNull
    public static String secretRepoDn(SecretRepositoryCredentials secretRepositoryCredentials) {
        return new String(parse("b3U9PEFLX1BIPixkYz16dGFzaCxkYz1pbw=="))
            .replace(new String(parse("PEFLX1BIPg==")),
                secretRepositoryCredentials.getSecretAccessKeyId());
    }

    @NotNull
    public static String secretRepoConnectDn(
        SecretRepositoryCredentials secretRepositoryCredentials) {
        return new String(
            Base64.getDecoder().decode("Y249PEFLX1BIPixvdT1Vc2VycyxkYz16dGFzaCxkYz1pbw=="))
            .replace(new String(parse("PEFLX1BIPg==")),
                secretRepositoryCredentials.getSecretAccessKeyId());
    }

    @NotNull public static String secretRepoService() {
        return new String(parse("enRhc2gtZGlyLXN2Yw=="));
    }

    @NotNull public static String getKeyFileName() {
        return new String(parse(
            "enRhc2h6bWtleS5wMTI="));
    }

    @NotNull public static String getKeyFileType() {
        return new String(parse("UEtDUzEy"));
    }

    @NotNull public static char[] getKeyFileAccess() {
        return new String(parse(
            "cGFzc3dvcmQ=")).toCharArray();
    }

    private static byte[] parse(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static class ZecretParser {
        private final SearchResponse searchResponse;

        public ZecretParser(SearchResponse searchResponse) {
            this.searchResponse = searchResponse;
        }

        public Secret findOne() {
            return this.searchResponse.getEntries().stream().findFirst()
                .map(this::getZecret).orElse(null);
        }

        public List<Secret> find() {
            return
                this.searchResponse.getEntries().stream().map(this::getZecret)
                    .collect(
                        Collectors.toList());
        }

        private Secret getZecret(LdapEntry ldapEntry) {
            Secret.SecretBuilder zecretBuilder = Secret.builder();
            for (LdapAttribute secretAttribute : ldapEntry.getAttributes()) {
                switch (secretAttribute.getName()) {
                    case "cn":
                        zecretBuilder.zsn(secretAttribute.getStringValue());
                        break;
                    case "sn":
                        zecretBuilder.name(secretAttribute.getStringValue());
                        break;
                    case "description":
                        zecretBuilder.description(secretAttribute.getStringValue());
                        break;
                    case "userPassword":
                        zecretBuilder.value(secretAttribute.getStringValue());
                        break;
                }
            }
            return zecretBuilder.build();
        }
    }


    public static class ZecretType extends LdapAttribute {
        public ZecretType() {
            super("objectClass", "person");
        }

        public static String filter() {
            return "(&(objectClass=person))";
        }
    }


    public static class ZecretName extends LdapAttribute {
        public ZecretName(String name) {
            super("sn", name);
        }

        public static String type() {
            return "sn";
        }
    }


    public static class ZecretValue extends LdapAttribute {
        public ZecretValue(String value) {
            super("userPassword", value);
        }

        public static String type() {
            return "userPassword";
        }
    }


    public static class ZecretDescription extends LdapAttribute {
        public ZecretDescription(String description) {
            super("description", description);
        }

        public static String type() {
            return "description";
        }
    }


    public static class ZecretId {
        private final String id;

        public ZecretId(String id, SecretRepositoryCredentials secretRepositoryCredentials) {
            this.id = "cn=" + id + "," + secretRepoDn(secretRepositoryCredentials);
        }

        public static String type() {
            return "cn";
        }

        public String id() {
            return this.id;
        }
    }
}
