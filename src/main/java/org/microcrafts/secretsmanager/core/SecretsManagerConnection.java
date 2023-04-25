package org.microcrafts.secretsmanager.core;

import org.ldaptive.*;
import org.microcrafts.openziti.ldap.ZitiLdapConnection;
import org.microcrafts.openziti.ldap.ZitiLdapConnectionConfig;
import org.microcrafts.secretsmanager.utils.SecretsManagerException;
import org.openziti.ZitiContext;

public class SecretsManagerConnection {

    private final ZitiLdapConnection zitiLdapConnection;

    private SecretsManagerConnection(ZitiContext zitiContext,
        ZitiLdapConnectionConfig zitiLdapConnectionConfig) {
        zitiLdapConnection = new ZitiLdapConnection(zitiContext, zitiLdapConnectionConfig);
    }

    public static synchronized SecretsManagerConnection getInstance(
        SecretsManagerContext secretsManagerContext) {
        return new SecretsManagerConnection(secretsManagerContext.getSecretRepoServiceContext(),
            secretsManagerContext.getSecretRepoConnectionConfig());
    }

    public void open() throws SecretsManagerException {
        try {
            zitiLdapConnection.open();
        } catch (LdapException e) {
            throw new SecretsManagerException(
                "Unable to open zecrets manager repository connection");
        }
    }

    public void close() {
        zitiLdapConnection.close();
    }

    public AddResponse addSecret(AddRequest addRequest) throws SecretsManagerException {
        OperationHandle<AddRequest, AddResponse> operation =
            zitiLdapConnection.operation(addRequest);
        try {
            return operation.execute();
        } catch (LdapException e) {
            throw new SecretsManagerException(
                "Unable to add secrets to the repository");
        }
    }

    public ModifyResponse updateSecret(ModifyRequest modifyRequest) throws SecretsManagerException {
        OperationHandle<ModifyRequest, ModifyResponse> operation =
            zitiLdapConnection.operation(modifyRequest);
        try {
            return operation.execute();
        } catch (LdapException e) {
            throw new SecretsManagerException(
                "Unable to update secrets in the repository");
        }
    }

    public SearchResponse searchSecret(SearchRequest searchRequest)
        throws SecretsManagerException {
        org.ldaptive.SearchOperationHandle searchOperationHandle =
            zitiLdapConnection.operation(searchRequest);
        try {
            return searchOperationHandle.execute();
        } catch (LdapException e) {
            throw new SecretsManagerException(
                "Unable to find secrets in the repository");
        }
    }

    public DeleteResponse deleteSecret(DeleteRequest deleteRequest) throws SecretsManagerException {
        OperationHandle<DeleteRequest, DeleteResponse> operation =
            zitiLdapConnection.operation(deleteRequest);
        try {
            return operation.execute();
        } catch (LdapException e) {
            throw new SecretsManagerException(
                "Unable to delete secret from the repository");
        }
    }

}
