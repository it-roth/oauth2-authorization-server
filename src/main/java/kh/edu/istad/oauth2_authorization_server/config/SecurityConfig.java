package kh.edu.istad.oauth2_authorization_server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.time.Instant;
import java.util.Base64;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	// A Spring Security filter chain for the Protocol Endpoints.
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, RegisteredClientRepository registeredClientRepository) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();

		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, (authorizationServer) ->
				authorizationServer
					.oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
					.clientAuthentication((clientAuth) -> clientAuth
						.authenticationConverter(request -> {
							String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
							if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
								return null;
							}
							String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
							if (!StringUtils.hasText(clientId)) {
								return null;
							}
							return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, null);
						})
						.authenticationProvider(new AuthenticationProvider() {
							@Override
							public Authentication authenticate(Authentication authentication) throws AuthenticationException {
								OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
								if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
									return null;
								}
								String clientId = clientAuthentication.getPrincipal().toString();
								RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
								if (registeredClient == null) {
									throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "client_id", null));
								}
								if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
									throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "authentication_method", null));
								}
								return new OAuth2ClientAuthenticationToken(registeredClient, ClientAuthenticationMethod.NONE, null);
							}

							@Override
							public boolean supports(Class<?> authentication) {
								return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
							}
						})
					)
			)
			.authorizeHttpRequests((authorize) ->
				authorize.anyRequest().authenticated()
			)
			// Redirect to the login page when not authenticated from the authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);

		return http.cors(Customizer.withDefaults()).build();
	}

	// A Spring Security filter chain for authentication.
	@Bean
	@Order(2)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the authorization server filter chain
			.formLogin(Customizer.withDefaults());

		return http.cors(Customizer.withDefaults()).build();
	}

	// Enable CORS
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		config.addAllowedOrigin("http://localhost:3000");
		config.addAllowedOrigin("http://localhost:4200");
		config.addAllowedOrigin("http://127.0.0.1:4200");
		config.setAllowCredentials(true);
		source.registerCorsConfiguration("/**", config);
		return source;
	}

	// An instance of UserDetailsService for retrieving users to authenticate.
	@Bean
	public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
		UserDetails user = User.builder()
				.username("user")
				.password(passwordEncoder.encode("password"))
				.roles("USER")
				.build();

		UserDetails admin = User.builder()
				.username("admin")
				.password(passwordEncoder.encode("admin123"))
				.roles("USER", "ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user, admin);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	// An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	// An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException("Failed to generate RSA key pair", ex);
		}
		return keyPair;
	}

	// An instance of JwtDecoder for decoding signed access tokens.
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	// An instance of AuthorizationServerSettings to configure Spring Authorization Server.
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	// An instance of OAuth2TokenCustomizer<JwtEncodingContext> for customizing the JWT access token claims with user authorities.
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
							.stream()
							.map(c -> c.replaceFirst("^ROLE_", ""))
							.collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
					claims.put("roles", roles);
					claims.put("username", context.getPrincipal().getName());
				});
			}
		};
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);

		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();

		StringKeyGenerator stringKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
		OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator = (context) -> {
			if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
				return null;
			}
			if (!context.getRegisteredClient().getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
			return new OAuth2RefreshToken(stringKeyGenerator.generateKey(), issuedAt, expiresAt);
		};

		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

}
