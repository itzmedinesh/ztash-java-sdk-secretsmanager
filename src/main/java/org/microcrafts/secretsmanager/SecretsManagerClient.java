package org.microcrafts.secretsmanager;

import lombok.extern.slf4j.Slf4j;
import org.ldaptive.*;
import org.microcrafts.secretsmanager.core.SecretsManagerConnection;
import org.microcrafts.secretsmanager.core.SecretsManagerContext;
import org.microcrafts.secretsmanager.core.SecretsManagerInitializer;
import org.microcrafts.secretsmanager.domain.*;
import org.microcrafts.secretsmanager.utils.SecretsManagerException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.microcrafts.secretsmanager.utils.SecretsManagerUtils.*;

@Slf4j public class SecretsManagerClient {

    private static SecretsManagerClient secretsManagerClient = null;

    private static SecretsManagerContext secretsManagerContext;

    private SecretsManagerClient(String tokenFilePath, String tokenFileName)
        throws SecretsManagerException {

        secretsManagerContext =
            new SecretsManagerInitializer(tokenFilePath, tokenFileName).getContext();
    }

    public static synchronized SecretsManagerClient init(String tokenFilePath, String tokenFileName)
        throws SecretsManagerException {
        if (secretsManagerClient == null)
            secretsManagerClient = new SecretsManagerClient(tokenFilePath, tokenFileName);
        return secretsManagerClient;
    }

    public CreateSecretResponse createSecret(CreateSecretRequest createSecretRequest)
        throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        String secretId = "zsn:";

        try {
            zecretRepositoryConnection.open();

            secretId = secretId + UUID.randomUUID();

            AddRequest addRequest = AddRequest.builder().dn(new ZecretId(secretId,
                    secretsManagerContext.getSecretRepositoryCredentials()).id())
                .attributes(new ZecretType(), new ZecretName(createSecretRequest.getName()),
                    new ZecretDescription(createSecretRequest.getDescription()),
                    new ZecretValue(createSecretRequest.getSecret())).build();

            AddResponse addResponse = zecretRepositoryConnection.addSecret(addRequest);

            if (!addResponse.isSuccess())
                throw new SecretsManagerException(
                    String.format("Unable to create secrets for request : %s",
                        createSecretRequest));

        } finally {
            zecretRepositoryConnection.close();
        }
        return CreateSecretResponse.builder().zsn(secretId).build();
    }


    public GetSecretValueResponse getSecretValue(GetSecretValueRequest getSecretValueRequest)
        throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        Secret secret;

        try {
            zecretRepositoryConnection.open();

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setBaseDn(new ZecretId(getSecretValueRequest.getZsn(),
                secretsManagerContext.getSecretRepositoryCredentials()).id());
            searchRequest.setFilter(ZecretType.filter());
            searchRequest.setReturnAttributes(ZecretId.type(), ZecretValue.type());

            SearchResponse searchResponse = zecretRepositoryConnection.searchSecret(searchRequest);

            if (!searchResponse.isSuccess())
                throw new SecretsManagerException("Unable to get secret value");

            secret = new ZecretParser(searchResponse).findOne();

            if (secret == null)
                throw new SecretsManagerException(
                    String.format("Secret not found for zsn %s", getSecretValueRequest.getZsn()));

        } finally {
            zecretRepositoryConnection.close();
        }

        return GetSecretValueResponse.builder().zsn(secret.getZsn())
            .secret(secret.getValue()).build();
    }

    public ListSecretsResponse listSecrets() throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        List<String> secretsList;

        try {
            zecretRepositoryConnection.open();

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setBaseDn(
                secretRepoDn(secretsManagerContext.getSecretRepositoryCredentials()));
            searchRequest.setFilter(ZecretType.filter());
            searchRequest.setReturnAttributes(ZecretId.type());

            SearchResponse searchResponse = zecretRepositoryConnection.searchSecret(searchRequest);

            if (!searchResponse.isSuccess())
                throw new SecretsManagerException("Unable to list secrets");

            if (!searchResponse.isSuccess())
                throw new SecretsManagerException(
                    "Unable to list secrets, secrets not found for this application");

            List<Secret> secrets = new ZecretParser(searchResponse).find();

            secretsList =
                secrets.stream().map(Secret::getZsn).collect(Collectors.toList());

        } finally {
            zecretRepositoryConnection.close();
        }

        return ListSecretsResponse.builder()
            .zsns(secretsList).build();
    }

    public DescribeSecretResponse describeSecret(DescribeSecretRequest describeSecretRequest)
        throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        Secret secret;

        try {
            zecretRepositoryConnection.open();

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.setBaseDn(new ZecretId(describeSecretRequest.getZsn(),
                secretsManagerContext.getSecretRepositoryCredentials()).id());
            searchRequest.setFilter(ZecretType.filter());
            searchRequest.setReturnAttributes(ZecretId.type(), ZecretName.type(),
                ZecretDescription.type(), ZecretValue.type());

            SearchResponse searchResponse = zecretRepositoryConnection.searchSecret(searchRequest);

            if (!searchResponse.isSuccess())
                throw new SecretsManagerException(String.format(
                    "Unable to describe secret, secret with zsn %s not found or invalid",
                    describeSecretRequest.getZsn()));

            secret = new ZecretParser(searchResponse).findOne();

            if (secret == null)
                throw new SecretsManagerException(
                    String.format("Secret not found with zsn %s", describeSecretRequest.getZsn()));

        } finally {
            zecretRepositoryConnection.close();
        }

        return DescribeSecretResponse.builder().zsn(secret.getZsn()).name(secret.getName())
            .secret(secret.getValue()).description(secret.getDescription()).build();
    }

    public UpdateSecretResponse updateSecret(UpdateSecretRequest updateSecretRequest)
        throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        try {
            zecretRepositoryConnection.open();

            ModifyRequest.Builder modifyRequestBuilder =
                ModifyRequest.builder().dn(new ZecretId(updateSecretRequest.getZsn(),
                    secretsManagerContext.getSecretRepositoryCredentials()).id());

            List<AttributeModification> attributeModifications = new ArrayList<>();

            if (updateSecretRequest.getDescription() != null)
                attributeModifications.add(new AttributeModification(
                    AttributeModification.Type.REPLACE,
                    new ZecretDescription(updateSecretRequest.getDescription())));

            if (updateSecretRequest.getName() != null)
                attributeModifications.add(new AttributeModification(
                    AttributeModification.Type.REPLACE,
                    new ZecretName(updateSecretRequest.getName())));

            if (updateSecretRequest.getSecret() != null)
                attributeModifications.add(new AttributeModification(
                    AttributeModification.Type.REPLACE,
                    new ZecretValue(updateSecretRequest.getSecret())));

            if (!attributeModifications.isEmpty()) {
                modifyRequestBuilder.modificiations(attributeModifications);
                ModifyResponse modifyResponse =
                    zecretRepositoryConnection.updateSecret(modifyRequestBuilder.build());

                if (!modifyResponse.isSuccess())
                    throw new SecretsManagerException(String.format(
                        "Unable to modify secret, secret with zsn %s not found or invalid",
                        updateSecretRequest.getZsn()));
                else
                    log.info("Secret with zsn {} successfully modified",
                        updateSecretRequest.getZsn());

            } else {
                throw new SecretsManagerException("Nothing to modify");
            }

        } finally {
            zecretRepositoryConnection.close();
        }

        return UpdateSecretResponse.builder().zsn(updateSecretRequest.getZsn()).build();
    }

    public DeleteSecretResponse deleteSecret(DeleteSecretRequest deleteSecretRequest)
        throws SecretsManagerException {

        SecretsManagerConnection zecretRepositoryConnection =
            SecretsManagerConnection.getInstance(secretsManagerContext);

        try {
            zecretRepositoryConnection.open();

            DeleteRequest deleteRequest =
                DeleteRequest.builder().dn(new ZecretId(deleteSecretRequest.getZsn(),
                    secretsManagerContext.getSecretRepositoryCredentials()).id()).build();

            DeleteResponse deleteResponse = zecretRepositoryConnection.deleteSecret(deleteRequest);

            if (!deleteResponse.isSuccess())
                throw new SecretsManagerException(String.format(
                    "Unable to delete  value, secret with zsn %s not found or invalid",
                    deleteSecretRequest.getZsn()));
            else
                log.info("Secret with zsn {} successfully deleted", deleteSecretRequest.getZsn());

        } finally {
            zecretRepositoryConnection.close();
        }

        return DeleteSecretResponse.builder().zsn(deleteSecretRequest.getZsn()).build();
    }
}
