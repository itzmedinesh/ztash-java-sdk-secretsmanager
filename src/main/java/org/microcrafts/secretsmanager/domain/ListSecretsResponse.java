package org.microcrafts.secretsmanager.domain;

import lombok.Builder;
import lombok.Value;

import java.util.ArrayList;
import java.util.List;

@Value
@Builder
public class ListSecretsResponse extends ArrayList {
    private List<String> zsns;
}
