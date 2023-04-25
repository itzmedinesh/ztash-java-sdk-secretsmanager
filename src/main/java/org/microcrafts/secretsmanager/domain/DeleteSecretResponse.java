package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

@Builder
@Value
public class DeleteSecretResponse {
    String zsn;
}
