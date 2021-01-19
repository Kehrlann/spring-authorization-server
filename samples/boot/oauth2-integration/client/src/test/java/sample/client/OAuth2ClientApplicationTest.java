package sample.client;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.springframework.test.web.servlet.MockMvc;
import sample.authorizationserver.OAuth2AuthorizationServerApplication;
import sample.resourceserver.OAuth2ResourceServerApplication;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


// Notes:
//
// Use-case:
// - A user that develops a bunch of services
// - One of the apps is a “frontend” app that acts as the OAuth 2 client
// - The other apps are OAuth 2 Resource Servers providing (I'm just doing one service for the sake of the example)
// - They rely on a single OAuth 2 provider, a OAuth 2.0-compliant authz server (or at least Spring-supported)
// - They want to make an integration/e2e test of the components they develop (client + resource servers)
//   - Probably using SpringBootTest
//
// Some early conclusions:
// - Users would need a _nice and easy_ way of starting an authz server, preferably on a dynamic port
//   - At the very least on a configurable port
//   - Thinking maybe an annotation, e.g. @EnableTestSpringAuthorizationServer
// - They'd need some sort of autoconfiguration of their client application so that it points at the correct (test) auth provider
//	 - <explore> is there a way that @SpringBootTest, coupled with @EnableTestSpringAuthorizationServer, auto-configures the client app ?
//   - <parking lot> what do we do when users have multiple auth providers ?
// - I assume they'd be starting their authorization server through SpringApplicationBuilder but that's very rough
// - They'd also need to point their resource servers at the correct validation mechanism for JWT (jwks uri, OIDC provider configuration uri, OAuth 2.0 server metadata)
//	 - For now we inject properties through SpringApplicationBuilder
//   - They could turn off jwt validation in their resource servers, but I don't think it makes sense for integration testing
//	 - <explore> Maybe you could autowire some sort of factory for configuring you resource server, linked to the TestSpringAuthorizationServer ?
//   - <parking lot> think about public-key jwt validation
//
// Misc notes on the changes on this branch:
// - This was very much quick-and-dirty, just to make it work
//	 - e.g., I used 3 spring boot applications, but the authz-server could probably be trimmed down to two config files
//	 - there's no specific isolation of any kind between the apps; they run in the same JVM, in different threads, but with the same classloader
//   - I moved packages around to avoid @SpringBootApplication package scanning conflicts


@RunWith(SpringRunner.class)
@SpringBootTest(classes = OAuth2ClientApplication.class)
@ContextConfiguration(initializers= OAuth2ClientApplicationTest.OAuth2ServersProperties.class)
@AutoConfigureMockMvc
public class OAuth2ClientApplicationTest {
	private static ConfigurableApplicationContext authorizationServer;
	private static ConfigurableApplicationContext resourceServer;

	@Autowired
	private MockMvc mockMvc;

	@BeforeClass
	public static void beforeClass() {
		// embedded-server-test: RUN
		// Run on dynamic port and get that port for the user to use
		authorizationServer = new SpringApplicationBuilder(OAuth2AuthorizationServerApplication.class)
				.properties("spring.config.name:embeddedauthorizationserver")	// Required to avoid clashes in MBean registration
				.properties("server.port:0")
				.application()
				.run();
		String authzServerPort = authorizationServer.getEnvironment().getProperty("local.server.port");
		// END embedded-server-test: RUN

		// Here the user would configure _their_ embedded resource server themselves
		// PROVIDED THAT they use the JWK Set URI to validate jwts
		// TODO: think about the public key case
		// TODO: could we easily provider a TestJwtDecoder that skips validation? SHOULD we ?
		resourceServer = new SpringApplicationBuilder(OAuth2ResourceServerApplication.class)
				.properties("spring.config.name:embeddedresourceserver")
				.properties("spring.security.oauth2.resourceserver.jwt.jwk-set-uri:http://localhost:" + authzServerPort + "/oauth2/jwks")
				.properties("server.port:0")
				.application()
				.run();
		String resourceServerPort = resourceServer.getEnvironment().getProperty("local.server.port");

		// embedded-server-test: CONFIGURE CLIENT
		// Nasty: override some property configurations for the client through static variables
		// TODO: find a better way to interact with OAuth2ClientProperties ; maybe auto-configure it ?
		OAuth2ServersProperties.AUTH_SERVER_URL = "http://localhost:" + authzServerPort;
		// END embedded-server-test: CONFIGURE CLIENT

		// Here would be the user configuring their app to point to _their_ resource server
		// That's not great, but this allows for dynamic port on the resource server without touching at the client app code
		OAuth2ServersProperties.RESOURCE_SERVER_URL = "http://localhost:" + resourceServerPort;
	}

	@AfterClass
	public static void afterClass() {
		authorizationServer.stop();
		resourceServer.stop();
	}

	@Test
	public void index() throws Exception {
		mockMvc
				.perform(get("/index"))
				.andExpect(status().isOk())
		.andExpect(content().string(containsString("Client Credentials")));
	}

	@Test
	public void authorize() throws Exception {
		mockMvc
				.perform(get("/authorize?grant_type=client_credentials"))
				.andExpect(status().isOk())
		.andExpect(content().string(containsString("Message 1")));
	}

	static class OAuth2ServersProperties implements ApplicationContextInitializer<ConfigurableApplicationContext> {
		// Helper class to point the clients at the right authz/resource servers
		static String AUTH_SERVER_URL;
		static String RESOURCE_SERVER_URL;

		@Override
		public void initialize(ConfigurableApplicationContext applicationContext) {
			TestPropertySourceUtils.addInlinedPropertiesToEnvironment(applicationContext,
					"spring.security.oauth2.client.provider.spring.authorization-uri=" + AUTH_SERVER_URL + "/oauth2/authorize",
					"spring.security.oauth2.client.provider.spring.token-uri=" + AUTH_SERVER_URL + "/oauth2/token",
					"messages.base-uri=" + RESOURCE_SERVER_URL + "/messages"
			);
		}
	}
}
