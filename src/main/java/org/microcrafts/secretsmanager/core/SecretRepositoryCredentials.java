package org.microcrafts.secretsmanager.core;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class SecretRepositoryCredentials {
    @NotNull String secretAccessKeyId;
    @NotNull String secretAccessKey;
    @NotNull String secretAccessIdentity;
}
