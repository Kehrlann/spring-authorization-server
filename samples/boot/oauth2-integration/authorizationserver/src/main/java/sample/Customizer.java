package sample;

import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Customizer {
	@Bean
	WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> portCustomizer() {
		return factory -> factory.setPort(1234);
	}
}
