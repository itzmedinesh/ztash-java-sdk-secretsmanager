package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class GetSecretValueResponse {
    String zsn;
    String secret;
}
