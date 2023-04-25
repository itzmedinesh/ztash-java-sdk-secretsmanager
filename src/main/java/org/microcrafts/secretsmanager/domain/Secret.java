package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class Secret {
    String zsn;
    String name;
    String value;
    String description;
}
