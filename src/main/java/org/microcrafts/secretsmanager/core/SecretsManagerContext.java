package org.microcrafts.secretsmanager.core;

import lombok.Builder;
import lombok.Value;
import org.microcrafts.openziti.ldap.ZitiLdapConnectionConfig;
import org.openziti.ZitiContext;

@Value
@Builder
public class SecretsManagerContext {
    SecretRepositoryCredentials secretRepositoryCredentials;
    ZitiContext secretRepoServiceContext;
    ZitiLdapConnectionConfig secretRepoConnectionConfig;
}
