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

@RunWith(SpringRunner.class)
@SpringBootTest(classes = OAuth2ClientApplication.class)
@ContextConfiguration(initializers= OAuth2ClientApplicationTest.Oauth2ServersProperties.class)
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
				.properties("spring.config.name:embeddedauthorizationserver")
				.properties("server.port:0")
				.application()
				.run();
		String authzServerPort = authorizationServer.getEnvironment().getProperty("local.server.port");
		// END embedded-server-test: RUN

		// Here the user would configure _their_ embedded resource server themselves
		// PROVIDED THAT they use the JWK Set URI to validate jwts
		// TODO: think about the public key case
		// TODO: could we easily provider a TestJwtDecder that skips validation? SHOULD we ?
		resourceServer = new SpringApplicationBuilder(OAuth2ResourceServerApplication.class)
				.properties("spring.config.name:embeddedresourceserver")
				.properties("spring.security.oauth2.resourceserver.jwt.jwk-set-uri:http://localhost:" + authzServerPort + "/oauth2/jwks")
				.properties("server.port:0")
				.application()
				.run();
		String resourceServerPort = resourceServer.getEnvironment().getProperty("local.server.port");

		// embedded-server-test: CONFIGURE CLIENT
		// Nasty, nasty, nasty: override some property configurations from the client
		// TODO: find a better way to interact with OAuth2ClientProperties ; maybe auto-configure it ?
		Oauth2ServersProperties.AUTH_SERVER_URL = "http://localhost:" + authzServerPort;
		// END embedded-server-test: CONFIGURE CLIENT

		// Here would be the user configuring their app to point to _their_ resource server
		// That's not great, but this allows for dynamic port on the resource server without touching at the client app code
		Oauth2ServersProperties.RESOURCE_SERVER_URL = "http://localhost:" + resourceServerPort;
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

	static class Oauth2ServersProperties implements ApplicationContextInitializer<ConfigurableApplicationContext> {
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
