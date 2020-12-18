package sample;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import sample.resourceserver.ResourceServerApplication;

public class Main {

	public static void main(String[] args) throws InterruptedException {
		ConfigurableApplicationContext authz = new SpringApplicationBuilder(OAuth2AuthorizationServerApplication.class)
				.application()
				.run();
		ConfigurableApplicationContext resource = new SpringApplicationBuilder(ResourceServerApplication.class)
				.application()
				.run();

		Thread.sleep(5000);
		System.out.println("STOP ! Hammertime.");

		authz.stop();
		resource.stop();
		System.out.println("bye");
	}
}
