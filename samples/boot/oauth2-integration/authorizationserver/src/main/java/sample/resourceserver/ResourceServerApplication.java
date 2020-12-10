package sample.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.admin.SpringApplicationAdminJmxAutoConfiguration;

// Quick work-around for JMX: otherwise, both apps try to register with MBeanServer
// using the same default name, "org.springframework.boot:type=Admin,name=SpringApplication"
@SpringBootApplication(exclude = {SpringApplicationAdminJmxAutoConfiguration.class})
public class ResourceServerApplication {
	public static void main(String[] args) {
		SpringApplication.run(ResourceServerApplication.class, args);
	}
}
