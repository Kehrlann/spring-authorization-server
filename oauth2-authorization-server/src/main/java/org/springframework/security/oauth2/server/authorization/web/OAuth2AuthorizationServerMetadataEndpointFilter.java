/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.core.http.converter.OAuth2AuthorizationServerMetadataHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@code Filter} that processes OAuth 2.0 Authorization Server Metadata Requests.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.0
 * @see ProviderSettings
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8414#section-3">3. Obtaining Authorization Server Metadata</a>
 */
public class OAuth2AuthorizationServerMetadataEndpointFilter extends OncePerRequestFilter {
	/**
	 * The default endpoint {@code URI} for OAuth 2.0 Authorization Server Metadata requests.
	 */
	public static final String DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI = "/.well-known/oauth-authorization-server";

	private final RequestMatcher requestMatcher;
	private final ProviderSettings providerSettings;
	private final OAuth2AuthorizationServerMetadataHttpMessageConverter authorizationServerMetadataHttpMessageConverter
			= new OAuth2AuthorizationServerMetadataHttpMessageConverter();

	public OAuth2AuthorizationServerMetadataEndpointFilter(ProviderSettings providerSettings) {
		Assert.notNull(providerSettings, "providerSettings cannot be null");
		this.providerSettings = providerSettings;
		this.requestMatcher = new AntPathRequestMatcher(
				DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI,
				HttpMethod.GET.name()
		);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.withDefaultClaims()
				.issuer(this.providerSettings.issuer())
				.authorizationEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.authorizationEndpoint()))
				.tokenEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.tokenEndpoint()))
				.tokenRevocationEndpoint(asUrl(this.providerSettings.issuer(), this.providerSettings.tokenRevocationEndpoint()))
				.jwkSetUri(asUrl(this.providerSettings.issuer(), this.providerSettings.jwkSetEndpoint()))
				.build();

		ServletServerHttpResponse resp = new ServletServerHttpResponse(response);
		this.authorizationServerMetadataHttpMessageConverter.write(
				authorizationServerMetadata, MediaType.APPLICATION_JSON, resp);
	}

	private static String asUrl(String issuer, String endpoint) {
		return UriComponentsBuilder.fromUriString(issuer).path(endpoint).toUriString();
	}
}
