package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class UpdateSecretRequest {
    String zsn;
    String name;
    String secret;
    String description;
}
