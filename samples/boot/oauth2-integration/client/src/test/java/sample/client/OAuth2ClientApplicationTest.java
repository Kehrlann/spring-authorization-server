package sample.client;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import sample.authorizationserver.OAuth2AuthorizationServerApplication;
import sample.resourceserver.OAuth2ResourceServerApplication;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = OAuth2ClientApplication.class)
@AutoConfigureMockMvc
public class OAuth2ClientApplicationTest {

	private static ConfigurableApplicationContext authorizationServer;
	private static ConfigurableApplicationContext resourceServer;

	@Autowired
	private MockMvc mockMvc;

	@BeforeClass
	public static void beforeClass() {
		authorizationServer = new SpringApplicationBuilder(OAuth2AuthorizationServerApplication.class)
				.properties("spring.config.name:embeddedauthorizationserver")
				.properties("server.port:9000")
				.application()
				.run();

		resourceServer = new SpringApplicationBuilder(OAuth2ResourceServerApplication.class)
				.properties("spring.config.name:embeddedresourceserver")
				.properties("spring.security.oauth2.resourceserver.jwt.jwk-set-uri:http://auth-server:9000/oauth2/jwks")
				.properties("server.port:8090")
				.application()
				.run();
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
}
