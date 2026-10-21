package kh.edu.istad.oauth2_authorization_server;

import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@SpringBootTest
class Oauth2AuthorizationServerApplicationTests {

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Test
	void contextLoads() {
	}

	@Test
	void seededClientsArePersistedWithTheirSecuritySettings() {
		RegisteredClient oidcClient = registeredClientRepository.findByClientId("oidc-client");
		RegisteredClient pkceClient = registeredClientRepository.findByClientId("postman-client");

		org.junit.jupiter.api.Assertions.assertNotNull(oidcClient);
		org.junit.jupiter.api.Assertions.assertTrue(oidcClient.getClientSettings().isRequireAuthorizationConsent());
		org.junit.jupiter.api.Assertions.assertNotNull(pkceClient);
		org.junit.jupiter.api.Assertions.assertTrue(pkceClient.getClientSettings().isRequireProofKey());
	}

	@Test
	void authorizationCanBeSavedAndRestoredFromJpa() {
		RegisteredClient client = registeredClientRepository.findByClientId("oidc-client");
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
				.id(UUID.randomUUID().toString())
				.principalName("jpa-roundtrip-test")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizedScopes(Set.of("read"))
				.build();

		authorizationService.save(authorization);
		try {
			OAuth2Authorization restored = authorizationService.findById(authorization.getId());

			org.junit.jupiter.api.Assertions.assertNotNull(restored);
			org.junit.jupiter.api.Assertions.assertEquals("jpa-roundtrip-test", restored.getPrincipalName());
			org.junit.jupiter.api.Assertions.assertEquals(Set.of("read"), restored.getAuthorizedScopes());
		} finally {
			authorizationService.remove(authorization);
		}
	}

}
