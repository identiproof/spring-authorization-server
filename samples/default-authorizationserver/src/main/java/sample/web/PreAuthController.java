package sample.web;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

/**
 * @author Darek Zbik
 */
@RestController
public class PreAuthController {
	private final OAuth2AuthorizationService authorizationService;
	private final RegisteredClientRepository registeredClientRepository;
	private final StringKeyGenerator authorizationCodeGenerator =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
	private final StringKeyGenerator noncnik =
			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

	public PreAuthController(final OAuth2AuthorizationService authorizationService, RegisteredClientRepository registeredClientRepository) {
		this.authorizationService = authorizationService;
		this.registeredClientRepository = registeredClientRepository;
	}

	@GetMapping("/issuer/preauth")
	public String initPreauthToken(
			@RequestParam(value = "pin", required = false) String pin,
			@RequestParam(value = "type", required = false) String type,
			@RequestParam(value = "nonce", required = false) String nonce,
			@RequestParam(value = "code_challenge", required = false) String code_challenge,
			@RequestParam(value = "credential_type", required = true) String credential_type) {
		/* Most of this logic is copied from OAuth2AuthorizationCodeRequestAuthenticationProvider */

		final HashMap<String, Object> params = new HashMap<>();

		params.put("credential_type",credential_type);

		if (StringUtils.hasText(code_challenge)) {
			params.put("code_challenge", code_challenge);
			params.put("code_challenge_method", "S256");
		}

		if (StringUtils.hasText(pin)) {
			params.put("pin", pin);
		}

		if (StringUtils.hasText(nonce)) {
			// it is initial nonce to be used (dirty hack as someone can use the same all the time)
			params.put("nonce", nonce);
		}
		else {
			params.put("nonce", noncnik.generateKey());
		}

		final RegisteredClient registeredClient = registeredClientRepository.findByClientId("web-client");

		final Collection<SimpleGrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"));
		final User user = new User("user1", "h", authorities);
		final UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(user, "password", authorities);

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
				OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
						.authorizationUri("/auth")
//						.scopes(new HashSet<>(Arrays.asList("scopes")))
						.scopes(Collections.singleton(credential_type))
						.state("abcd")
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
