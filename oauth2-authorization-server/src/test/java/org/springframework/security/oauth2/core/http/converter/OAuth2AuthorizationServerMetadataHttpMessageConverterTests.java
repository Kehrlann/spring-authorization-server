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
package org.springframework.security.oauth2.core.http.converter;


import org.junit.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationServerMetadata;

import java.net.URL;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OAuth2AuthorizationServerMetadataHttpMessageConverter}
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationServerMetadataHttpMessageConverterTests {
	private final OAuth2AuthorizationServerMetadataHttpMessageConverter messageConverter = new OAuth2AuthorizationServerMetadataHttpMessageConverter();

	@Test
	public void supportsWhenOAuth2AuthorizationServerMetadataThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2AuthorizationServerMetadata.class)).isTrue();
	}

	@Test
	public void setAuthorizationServerMetadataParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setAuthorizationServerMetadataParametersConverter(null));
	}

	@Test
	public void setAuthorizationServerMetadataConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.messageConverter.setAuthorizationServerMetadataConverter(null));
	}

	@Test
	public void readInternalWhenRequiredParametersThenSuccess() throws Exception {
		// @formatter:off
		String serverMetadataResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(serverMetadataResponse.getBytes(), HttpStatus.OK);
		OAuth2AuthorizationServerMetadata serverMetadata = this.messageConverter
				.readInternal(OAuth2AuthorizationServerMetadata.class, response);

		assertThat(serverMetadata.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(serverMetadata.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(serverMetadata.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(serverMetadata.getJwkSetUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(serverMetadata.getResponseTypes()).containsExactly("code");
		assertThat(serverMetadata.getScopes()).isNull();
		assertThat(serverMetadata.getGrantTypes()).isNull();
		assertThat(serverMetadata.getTokenEndpointAuthenticationMethods()).isNull();
		assertThat(serverMetadata.getCodeChallengeMethods()).isNull();
		assertThat(serverMetadata.getTokenRevocationEndpoint()).isNull();
		assertThat(serverMetadata.getTokenRevocationEndpointAuthenticationMethods()).isNull();
	}

	@Test
	public void readInternalWhenValidParametersThenSuccess() throws Exception {
		// @formatter:off
		String serverMetadataResponse = "{\n"
				+ "		\"issuer\": \"https://example.com/issuer1\",\n"
				+ "		\"authorization_endpoint\": \"https://example.com/issuer1/oauth2/authorize\",\n"
				+ "		\"token_endpoint\": \"https://example.com/issuer1/oauth2/token\",\n"
				+ "		\"revocation_endpoint\": \"https://example.com/issuer1/oauth2/revoke\",\n"
				+ "		\"jwks_uri\": \"https://example.com/issuer1/oauth2/jwks\",\n"
				+ "		\"response_types_supported\": [\"code\"],\n"
				+ "		\"grant_types_supported\": [\"authorization_code\", \"client_credentials\"],\n"
				+ "		\"scopes_supported\": [\"openid\"],\n"
				+ "		\"token_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"revocation_endpoint_auth_methods_supported\": [\"client_secret_basic\"],\n"
				+ "		\"code_challenge_methods_supported\": [\"plain\",\"S256\"],\n"
				+ "		\"custom_claim\": \"value\",\n"
				+ "		\"custom_collection_claim\": [\"value1\", \"value2\"]\n"
				+ "}\n";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(serverMetadataResponse.getBytes(), HttpStatus.OK);
		OAuth2AuthorizationServerMetadata serverMetadata = this.messageConverter
				.readInternal(OAuth2AuthorizationServerMetadata.class, response);

		assertThat(serverMetadata.getClaims()).hasSize(13);
		assertThat(serverMetadata.getIssuer()).isEqualTo(new URL("https://example.com/issuer1"));
		assertThat(serverMetadata.getAuthorizationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/authorize"));
		assertThat(serverMetadata.getTokenEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/token"));
		assertThat(serverMetadata.getTokenRevocationEndpoint()).isEqualTo(new URL("https://example.com/issuer1/oauth2/revoke"));
		assertThat(serverMetadata.getJwkSetUri()).isEqualTo(new URL("https://example.com/issuer1/oauth2/jwks"));
		assertThat(serverMetadata.getResponseTypes()).containsExactly("code");
		assertThat(serverMetadata.getGrantTypes()).containsExactlyInAnyOrder("authorization_code", "client_credentials");
		assertThat(serverMetadata.getScopes()).containsExactly("openid");
		assertThat(serverMetadata.getTokenEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(serverMetadata.getTokenRevocationEndpointAuthenticationMethods()).containsExactly("client_secret_basic");
		assertThat(serverMetadata.getCodeChallengeMethods()).containsExactlyInAnyOrder("plain", "S256");
		assertThat(serverMetadata.getClaimAsString("custom_claim")).isEqualTo("value");
		assertThat(serverMetadata.getClaimAsStringList("custom_collection_claim")).containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void readInternalWhenFailingConverterThenThrowException() {
		String errorMessage = "this is not a valid converter";
		this.messageConverter.setAuthorizationServerMetadataConverter(source -> {
			throw new RuntimeException(errorMessage);
		});
		MockClientHttpResponse response = new MockClientHttpResponse("{}".getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerMetadata.class, response))
				.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Metadata")
				.withMessageContaining(errorMessage);
	}

	@Test
	public void readInternalWhenInvalidOAuth2AuthorizationServerMetadataThenThrowException() {
		String providerConfigurationResponse = "{ \"issuer\": null }";
		MockClientHttpResponse response = new MockClientHttpResponse(providerConfigurationResponse.getBytes(), HttpStatus.OK);

		assertThatExceptionOfType(HttpMessageNotReadableException.class)
				.isThrownBy(() -> this.messageConverter.readInternal(OAuth2AuthorizationServerMetadata.class, response))
				.withMessageContaining("An error occurred reading the OAuth 2.0 Authorization Server Metadata")
				.withMessageContaining("issuer cannot be null");
	}

	@Test
	public void writeInternalWhenOAuth2AuthorizationServerMetadataThenSuccess() {
		OAuth2AuthorizationServerMetadata serverMetadata =
				OAuth2AuthorizationServerMetadata
						.builder()
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
						.claim("custom_claim", "value")
						.claim("custom_collection_claim", Arrays.asList("value1", "value2"))
						.build();
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();

		this.messageConverter.writeInternal(serverMetadata, outputMessage);

		String serverMetadataResponse = outputMessage.getBodyAsString();
		assertThat(serverMetadataResponse).contains("\"issuer\":\"https://example.com/issuer1\"");
		assertThat(serverMetadataResponse).contains("\"authorization_endpoint\":\"https://example.com/issuer1/oauth2/authorize\"");
		assertThat(serverMetadataResponse).contains("\"token_endpoint\":\"https://example.com/issuer1/oauth2/token\"");
		assertThat(serverMetadataResponse).contains("\"revocation_endpoint\":\"https://example.com/issuer1/oauth2/revoke\"");
		assertThat(serverMetadataResponse).contains("\"jwks_uri\":\"https://example.com/issuer1/oauth2/jwks\"");
		assertThat(serverMetadataResponse).contains("\"scopes_supported\":[\"openid\"]");
		assertThat(serverMetadataResponse).contains("\"response_types_supported\":[\"code\"]");
		assertThat(serverMetadataResponse).contains("\"grant_types_supported\":[\"authorization_code\",\"client_credentials\"]");
		assertThat(serverMetadataResponse).contains("\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(serverMetadataResponse).contains("\"revocation_endpoint_auth_methods_supported\":[\"client_secret_basic\"]");
		assertThat(serverMetadataResponse).contains("\"code_challenge_methods_supported\":[\"plain\",\"S256\"]");
		assertThat(serverMetadataResponse).contains("\"custom_claim\":\"value\"");
		assertThat(serverMetadataResponse).contains("\"custom_collection_claim\":[\"value1\",\"value2\"]");

	}

	@Test
	public void writeInternalWhenWriteFailsThenThrowsException() {
		String errorMessage = "this is not a valid converter";
		Converter<OAuth2AuthorizationServerMetadata, Map<String, Object>> failingConverter =
				source -> {
					throw new RuntimeException(errorMessage);
				};
		this.messageConverter.setAuthorizationServerMetadataParametersConverter(failingConverter);

		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		OAuth2AuthorizationServerMetadata serverMetadata =
				OAuth2AuthorizationServerMetadata
						.builder()
						.issuer("https://example.com/issuer1")
						.authorizationEndpoint("https://example.com/issuer1/oauth2/authorize")
						.tokenEndpoint("https://example.com/issuer1/oauth2/token")
						.jwkSetUri("https://example.com/issuer1/oauth2/jwks")
						.responseType("code")
						.build();

		assertThatExceptionOfType(HttpMessageNotWritableException.class)
				.isThrownBy(() -> this.messageConverter.writeInternal(serverMetadata, outputMessage))
				.withMessageContaining("An error occurred writing the OAuth 2.0 Authorization Server Metadata")
				.withMessageContaining(errorMessage);
	}
}
