package kh.edu.istad.oauth2_authorization_server.init;

import java.time.Duration;
import java.util.UUID;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

	private final RegisteredClientRepository clientRepository;
	private final PasswordEncoder passwordEncoder;

	public DataInitializer(RegisteredClientRepository clientRepository, PasswordEncoder passwordEncoder) {
		this.clientRepository = clientRepository;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public void run(String... args) {
		RegisteredClient existingOidc = this.clientRepository.findByClientId("oidc-client");
		String oidcId = (existingOidc != null) ? existingOidc.getId() : UUID.randomUUID().toString();
		RegisteredClient oidcClient = RegisteredClient.withId(oidcId)
				.clientId("oidc-client")
				.clientSecret(this.passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
				.redirectUri("http://localhost:8080/login/oauth2/code/oidc-client")
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.postLogoutRedirectUri("http://127.0.0.1:8080/")
				.postLogoutRedirectUri("http://localhost:8080/")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(true)
						.requireProofKey(false)
						.build())
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).build())
				.build();
		this.clientRepository.save(oidcClient);

		RegisteredClient existingPublic = this.clientRepository.findByClientId("public-client");
		String publicId = (existingPublic != null) ? existingPublic.getId() : UUID.randomUUID().toString();
		RegisteredClient publicClient = RegisteredClient.withId(publicId)
				.clientId("public-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://127.0.0.1:4200")
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(true)
						.requireProofKey(true) // Enforces PKCE RFC 7636
						.build())
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(15)).build())
				.build();
		this.clientRepository.save(publicClient);

		RegisteredClient existingPostman = this.clientRepository.findByClientId("postman-client");
		String postmanId = (existingPostman != null) ? existingPostman.getId() : UUID.randomUUID().toString();
		RegisteredClient postmanClient = RegisteredClient.withId(postmanId)
				.clientId("postman-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("https://oauth.pstmn.io/v1/callback")
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
				.redirectUri("http://localhost:8080/login/oauth2/code/oidc-client")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("read")
				.scope("write")
				.clientSettings(ClientSettings.builder()
						.requireAuthorizationConsent(false) // Direct authorize or consent
						.requireProofKey(true) // Enforces PKCE with code_challenge and code_verifier
						.build())
				.tokenSettings(TokenSettings.builder()
						.accessTokenTimeToLive(Duration.ofMinutes(30))
						.reuseRefreshTokens(true)
						.build())
				.build();
		this.clientRepository.save(postmanClient);
	}
}
