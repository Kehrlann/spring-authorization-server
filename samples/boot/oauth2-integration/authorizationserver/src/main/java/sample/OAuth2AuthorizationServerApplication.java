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
package sample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import sample.resourceserver.ResourceServerApplication;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@SpringBootApplication(scanBasePackages = {"sample.config"})
public class OAuth2AuthorizationServerApplication {

	private final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationServerApplication.class);
//	private Thread resourceServerThread;

	public static void main(String[] args) {
		SpringApplication.run(OAuth2AuthorizationServerApplication.class, args);
	}

//	@Override
//	public void run(String... args) {
//		logger.info("Hello 🥰🥳");
//		resourceServerThread = new Thread(
//				() -> SpringApplication.run(ResourceServerApplication.class, new String[]{})
//		);
//		resourceServerThread.start();
//		logger.info("Running 🏃👟‍");
//	}
}
