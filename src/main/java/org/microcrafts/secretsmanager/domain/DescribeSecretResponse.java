package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class DescribeSecretResponse {
    String zsn;
    String name;
    String secret;
    String description;
}
