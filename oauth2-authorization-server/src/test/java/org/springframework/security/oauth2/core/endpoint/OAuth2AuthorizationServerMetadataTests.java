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
package org.springframework.security.oauth2.core.endpoint;

import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerMetadata.Builder;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationServerMetadata}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerMetadataTests {
	private final Builder minimalConfigurationBuilder =
			OAuth2AuthorizationServerMetadata.builder()
					.issuer("https://example.com/issuer1")
					.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
					.tokenEndpoint("https://example.com/issuer1/oauth2/token")
					.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
					.scope("openid")
					.responseType("code");

	@Test
	public void buildWhenAllRequiredClaimsAndAdditionalClaimsThenCreated() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
				.tokenEndpoint("https://example.com/issuer1/oauth2/token")
				.tokenRevocationEndpoint("https://example.com/issuer1/oauth2/revoke")
				.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
				.scope("openid")
				.responseType("code")
				.grantType("authorization_code")
				.grantType("client_credentials")
				.tokenEndpointAuthenticationMethod("client_secret_basic")
				.tokenRevocationEndpointAuthenticationMethod("client_secret_basic")
				.codeChallengeMethod("plain")
				.codeChallengeMethod("S256")
				.claim("a-claim", "a-value")
				.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getJwkSetUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials");
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).containsExactlyInAnyOrder("plain", "S256");
		assertThat(authorizationServerMetadata.getClaimAsString("a-claim")).isEqualTo("a-value");
	}

	@Test
	public void buildWhenOnlyRequiredClaimsThenCreated() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.builder()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
				.tokenEndpoint("https://example.com/issuer1/oauth2/token")
				.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
				.scope("openid")
				.responseType("code")
				.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(authorizationServerMetadata.getJwkSetUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
	}

	@Test
	public void buildFromClaimsThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "https://example.com/issuer1");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, "https://example.com/issuer1/oauth2/authorize");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "https://example.com/issuer1/oauth2/token");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "https://example.com/issuer1/oauth2/jwks");
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put("some-claim", "some-value");

		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.withClaims(claims).build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(authorizationServerMetadata.getJwkSetUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
		assertThat(authorizationServerMetadata.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void buildFromClaimsWhenUsingUrlsThenCreated() {
		HashMap<String, Object> claims = new HashMap<>();
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, url("https://example.com/issuer1"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, url("https://example.com/issuer1/oauth2/authorize"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, url("https://example.com/issuer1/oauth2/token"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, url("https://example.com/issuer1/oauth2/revoke"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, url("https://example.com/issuer1/oauth2/jwks"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED, Collections.singletonList("openid"));
		claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.singletonList("code"));
		claims.put("some-claim", "some-value");

		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata.withClaims(claims).build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenRevocationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/revoke"));
		assertThat(authorizationServerMetadata.getJwkSetUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).isNull();
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).isNull();
		assertThat(authorizationServerMetadata.getClaimAsString("some-claim")).isEqualTo("some-value");
	}

	@Test
	public void buildWhenDefaultClaimsThenDefaultsSet() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = OAuth2AuthorizationServerMetadata
				.withDefaultClaims()
				.issuer("https://example.com/issuer1")
				.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
				.tokenEndpoint("https://example.com/issuer1/oauth2/token")
				.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
				.build();

		assertThat(authorizationServerMetadata.getIssuer()).isEqualTo(url("https://example.com/issuer1"));
		assertThat(authorizationServerMetadata.getAuthorizationEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/authorize"));
		assertThat(authorizationServerMetadata.getTokenEndpoint()).isEqualTo(url("https://example.com/issuer1/oauth2/token"));
		assertThat(authorizationServerMetadata.getTokenEndpointAuthenticationMethods()).containsExactlyInAnyOrder("client_secret_basic", "client_secret_post");
		assertThat(authorizationServerMetadata.getJwkSetUri()).isEqualTo(url("https://example.com/issuer1/oauth2/jwks"));
		assertThat(authorizationServerMetadata.getScopes()).containsExactly("openid");
		assertThat(authorizationServerMetadata.getResponseTypes()).containsExactly("code");
		assertThat(authorizationServerMetadata.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials", "refresh_token");
		assertThat(authorizationServerMetadata.getTokenRevocationEndpointAuthenticationMethods()).containsExactlyInAnyOrder("client_secret_basic", "client_secret_post");
		assertThat(authorizationServerMetadata.getCodeChallengeMethods()).containsExactlyInAnyOrder("plain", "S256");
	}

	@Test
	public void withClaimsWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationServerMetadata.withClaims(null))
				.withMessage("claims cannot be empty");
	}

	@Test
	public void withClaimsWhenMissingRequiredClaimsThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationServerMetadata.withClaims(Collections.emptyMap()))
				.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenCalledTwiceThenGeneratesTwoConfigurations() {
		OAuth2AuthorizationServerMetadata first = this.minimalConfigurationBuilder
				.grantType("client_credentials")
				.build();

		OAuth2AuthorizationServerMetadata second = this.minimalConfigurationBuilder
				.claims((claims) ->
						{
							LinkedHashSet<String> newGrantTypes = new LinkedHashSet<>();
							newGrantTypes.add("authorization_code");
							newGrantTypes.add("custom_grant");
							claims.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, newGrantTypes);
						}
				)
				.build();

		assertThat(first.getGrantTypes()).containsExactly("client_credentials");
		assertThat(second.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "custom_grant");
	}

	@Test
	public void buildWhenEmptyClaimsThenOmitted() {
		OAuth2AuthorizationServerMetadata authorizationServerMetadata = this.minimalConfigurationBuilder
				.claim("some-claim", Collections.emptyList())
				.claims(claims -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, Collections.emptyList()))
				.build();

		assertThat(authorizationServerMetadata.getClaimAsStringList("some-claim")).isNull();
		assertThat(authorizationServerMetadata.getClaimAsStringList(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED)).isNull();
	}

	@Test
	public void buildWhenMissingIssuerThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.ISSUER));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("issuer cannot be null");
	}

	@Test
	public void buildWhenIssuerIsNotAnUrlThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, "not an url"));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessageStartingWith("issuer must be a valid URL");
	}

	@Test
	public void buildWhenMissingAuthorizationEndpointThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("authorizationEndpoint cannot be null");
	}

	@Test
	public void buildWhenAuthorizationEndpointIsNotAnUrlThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessageStartingWith("authorizationEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingTokenEndpointThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("tokenEndpoint cannot be null");
	}

	@Test
	public void buildWhenTokenEndpointIsNotAnUrlThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, "not an url"));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessageStartingWith("tokenEndpoint must be a valid URL");
	}

	@Test
	public void buildWhenMissingJwksUriThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("jwksUri cannot be null");
	}

	@Test
	public void buildWhenJwksUriIsNotAnUrlThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, "not an url"));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessageStartingWith("jwksUri must be a valid URL");
	}

	@Test
	public void buildWhenMissingResponseTypesThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("responseTypes cannot be null");
	}

	@Test
	public void buildWhenResponseTypesNotListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, "not-a-list"));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessageStartingWith("responseTypes must be of type List");
	}

	@Test
	public void buildWhenResponseTypesEmptyListThenThrowIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED, Collections.emptyList()));

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("responseTypes cannot be empty");
	}

	@Test
	public void buildWhenInvalidTokenRevocationEndpointThenThrowsIllegalArgumentException() {
		Builder builder = this.minimalConfigurationBuilder
				.tokenRevocationEndpoint("not a valid URL");

		assertThatIllegalArgumentException()
				.isThrownBy(builder::build)
				.withMessage("tokenRevocationEndpoint must be a valid URL");
	}

	@Test
	public void responseTypesWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.responseType("should-be-removed")
				.responseTypes(responseTypes -> {
					responseTypes.clear();
					responseTypes.add("some-response-type");
				})
				.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void responseTypesWhenNotPresentAndAddingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.claims(claims -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED))
				.responseTypes(responseTypes -> responseTypes.add("some-response-type"))
				.build();

		assertThat(configuration.getResponseTypes()).containsExactly("some-response-type");
	}

	@Test
	public void scopesWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.scope("should-be-removed")
				.scopes(scopes -> {
					scopes.clear();
					scopes.add("some-scope");
				})
				.build();

		assertThat(configuration.getScopes()).containsExactly("some-scope");
	}

	@Test
	public void grantTypesWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.grantType("should-be-removed")
				.grantTypes(grantTypes -> {
					grantTypes.clear();
					grantTypes.add("some-grant-type");
				})
				.build();

		assertThat(configuration.getGrantTypes()).containsExactly("some-grant-type");
	}

	@Test
	public void tokenEndpointAuthenticationMethodsWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.tokenEndpointAuthenticationMethod("should-be-removed")
				.tokenEndpointAuthenticationMethods(authMethods -> {
					authMethods.clear();
					authMethods.add("some-authentication-method");
				})
				.build();

		assertThat(configuration.getTokenEndpointAuthenticationMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void tokenRevocationEndpointAuthenticationMethodsWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.tokenRevocationEndpointAuthenticationMethod("should-be-removed")
				.tokenRevocationEndpointAuthenticationMethods(authMethods -> {
					authMethods.clear();
					authMethods.add("some-authentication-method");
				})
				.build();

		assertThat(configuration.getTokenRevocationEndpointAuthenticationMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void codeChallengeMethodsMethodsWhenAddingOrRemovingThenCorrectValues() {
		OAuth2AuthorizationServerMetadata configuration = this.minimalConfigurationBuilder
				.codeChallengeMethod("should-be-removed")
				.codeChallengeMethods(codeChallengeMethods -> {
					codeChallengeMethods.clear();
					codeChallengeMethods.add("some-authentication-method");
				})
				.build();

		assertThat(configuration.getCodeChallengeMethods()).containsExactly("some-authentication-method");
	}

	@Test
	public void claimWhenNameIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationServerMetadata.builder().claim(null, "value"))
				.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> OAuth2AuthorizationServerMetadata.builder().claim("claim-name", null))
				.withMessage("value cannot be null");
	}

	@Test
	public void claimsWhenRemovingClaimThenNotPresent() {
		OAuth2AuthorizationServerMetadata configuration =
				this.minimalConfigurationBuilder
						.grantType("some-grant-type")
						.claims((claims) -> claims.remove(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED))
						.build();
		assertThat(configuration.getGrantTypes()).isNull();
	}

	@Test
	public void claimsWhenAddingClaimThenPresent() {
		OAuth2AuthorizationServerMetadata configuration =
				this.minimalConfigurationBuilder
						.claims((claims) -> claims.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED, "authorization_code"))
						.build();
		assertThat(configuration.getGrantTypes()).containsExactly("authorization_code");
	}

	private static URL url(String urlString) {
		try {
			return new URL(urlString);
		} catch (Exception ex) {
			throw new IllegalArgumentException("urlString must be a valid URL and valid URI");
		}
	}
}
