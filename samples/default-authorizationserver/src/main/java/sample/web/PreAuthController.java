package sample.web;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2PreAuthCodeAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Set;
import java.util.UUID;

import static org.springframework.security.oauth2.server.authorization.web.authentication.AnonymousPreAuthAuthenticationConverter.DEFAULT_PRE_AUTH_CLIENT;

/**
 * @author Darek Zbik
 */
@RestController
public class PreAuthController implements Cloneable{
	private final OAuth2AuthorizationService authorizationService;
	private final RegisteredClientRepository registeredClientRepository;
	private final StringKeyGenerator authorizationCodeGenerator =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	public PreAuthController(final OAuth2AuthorizationService authorizationService, RegisteredClientRepository registeredClientRepository) {
		this.authorizationService = authorizationService;
		this.registeredClientRepository = registeredClientRepository;
	}

	@CrossOrigin // to allow calls from swagger running separately
	@PostMapping(path = "/issuer/preauth", produces = MediaType.TEXT_PLAIN_VALUE)
	public String initPreauthToken(
			@RequestParam(value = "pin", required = false) String pin,
			@RequestParam(value = "type", required = true) Set<String> types,
			@RequestParam(value = "user_id", required = false) String userId,
			@RequestParam(value = "client_id", required = false) String clientId,
			@RequestParam(value = "code_challenge", required = false) String code_challenge) {
		/* Most of this logic is copied from OAuth2AuthorizationCodeRequestAuthenticationProvider */
		final HashMap<String, Object> params = new HashMap<>();

		if (StringUtils.hasText(code_challenge)) {
			params.put("code_challenge", code_challenge);
			params.put("code_challenge_method", "S256");
		}

		RegisteredClient registeredClient = registeredClientRepository.findByClientId(DEFAULT_PRE_AUTH_CLIENT);
		if(StringUtils.hasText(clientId)) {
			registeredClient = registeredClientRepository.findByClientId(clientId);
			if(null == registeredClient) {
				//currently no-auth to auth server is set - so refresh token won't work
				registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId(clientId)
						.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.authorizationGrantType(OAuth2PreAuthCodeAuthenticationConverter.PRE_AUTH_CODE_GRANT_TYPE)
						.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
						.redirectUri("http://127.0.0.1:8080/authorized")
						.scope(OidcScopes.OPENID)
						.scope("message.read")
						.scope("message.write")
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(667)).build())
						.build();
				registeredClientRepository.save(registeredClient);
			}
		}

		if (StringUtils.hasText(pin)) {
			params.put("pin", pin);
		}

		final User user = new User(StringUtils.trimAllWhitespace(userId), "*****",
				Collections.emptyList());
		final UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(user, null,
				Collections.emptyList());

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
						.authorizationUri("/auth")
						.scopes(Collections.unmodifiableSet(types))
						.additionalParameters(params)
						.consent(false)
						.build();

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
				.scopes(authorizationCodeRequestAuthentication.getScopes())
				.state(authorizationCodeRequestAuthentication.getState())
				.additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
				.build();


		OAuth2AuthorizationCode authorizationCode = generatePreAuthToken();

		OAuth2Authorization authorization = authorizationBuilder(registeredClient, principal, authorizationRequest)
				.token(authorizationCode)
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizationRequest.getScopes())
				.build();

		authorizationService.save(authorization);
		return authorizationCode.getTokenValue();
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient, Authentication principal,
			OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(principal.getName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), principal)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private OAuth2AuthorizationCode generatePreAuthToken() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(66, ChronoUnit.MINUTES);        // TODO Allow configuration for authorization code time-to-live
		return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
	}
}
