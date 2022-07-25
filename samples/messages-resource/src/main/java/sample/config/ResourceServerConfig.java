/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import org.apache.tomcat.util.net.SSLImplementation;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@EnableWebSecurity
public class ResourceServerConfig {

	// @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.mvcMatcher("/credential/**")
				.authorizeRequests()
					.mvcMatchers("/credential/**").access("hasAuthority('SCOPE_message.read')")
					.and()
			.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(createConverter());
		return http.build();
	}
	// @formatter:on

	public Converter<Jwt, AbstractAuthenticationToken> createConverter(){
		return jwt -> new IssuerAuthenticationToken(jwt,jwt.getSubject(), ((List<String>) jwt.getClaims().get("scope")));
	}

	public static class IssuerAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<Jwt> {

		protected IssuerAuthenticationToken(final Jwt token, final String principal, List<String> role) {
			super(token, principal, null, role.stream().map(string -> new SimpleGrantedAuthority("SCOPE_"+string)).collect(Collectors.toList()));
			this.setAuthenticated(true);
		}

		@Override
		public Map<String, Object> getTokenAttributes() {
			return this.getToken().getClaims();
		}
	}

}
