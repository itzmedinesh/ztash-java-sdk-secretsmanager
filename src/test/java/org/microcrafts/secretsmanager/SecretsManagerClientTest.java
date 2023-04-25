package org.microcrafts.secretsmanager;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.microcrafts.secretsmanager.domain.*;
import org.microcrafts.secretsmanager.utils.SecretsManagerException;

@Slf4j
public class SecretsManagerClientTest {

    private static SecretsManagerClient secretsManagerClient;

    @BeforeAll
    public static void setup() throws SecretsManagerException {
        secretsManagerClient = SecretsManagerClient.init("/Users/dineshsubramanian/zecret-mgr-home",
            "apptwentythree.jwt");
    }

    @Test
    public void testCreateSecrets() throws SecretsManagerException {
        CreateSecretRequest createSecretRequest =
            CreateSecretRequest.builder().name("MyFifthAppPass")
                .description("My Fifth Application Credential").secret("fifthapppass").build();

        CreateSecretResponse zecretCreateResponse =
            secretsManagerClient.createSecret(createSecretRequest);

        log.info("Create secret response : {}", zecretCreateResponse);
    }

    @Test
    public void testListSecrets() throws SecretsManagerException {

        ListSecretsResponse zecretCreateResponse =
            secretsManagerClient.listSecrets();

        log.info("List secrets response : {}", zecretCreateResponse);
    }

    @Test
    public void testDescribeSecret() throws SecretsManagerException {

        DescribeSecretResponse zecretDescribeResponse =
            secretsManagerClient.describeSecret(
                DescribeSecretRequest.builder().zsn("zsn:6a5536ee-f816-458a-a9cb-14406e73d57b")
                    .build());

        log.info("Describe secret response : {}", zecretDescribeResponse);
    }

    @Test
    public void testUpdateSecret() throws SecretsManagerException {

        //zsn:5bdbee91-ea49-4348-937e-b58b61d803d7, zsn:6a5536ee-f816-458a-a9cb-14406e73d57b

        UpdateSecretResponse zecretUpdateResponse =
            secretsManagerClient.updateSecret(
                UpdateSecretRequest.builder().zsn("zsn:6a5536ee-f816-458a-a9cb-14406e73d57b").description("My Fifth Application Secret")
                    .build());

        log.info("Update secret response : {}", zecretUpdateResponse);
    }

    @Test
    public void testGetSecretValue() throws SecretsManagerException {

        //zsn:5bdbee91-ea49-4348-937e-b58b61d803d7

        GetSecretValueResponse getSecretValueResponse =
            secretsManagerClient.getSecretValue(
                GetSecretValueRequest.builder().zsn("zsn:5bdbee91-ea49-4348-937e-b58b61d803d7")
                    .build());

        log.info("Get secret value response : {}", getSecretValueResponse);
    }

    @Test
    public void testDeleteSecretValue() throws SecretsManagerException {

        DeleteSecretResponse deleteSecretResponse =
            secretsManagerClient.deleteSecret(
                DeleteSecretRequest.builder().zsn("zsn:6a5536ee-f816-458a-a9cb-14406e73d57b")
                    .build());

        log.info("Delete secret response : {}", deleteSecretResponse);
    }

}
