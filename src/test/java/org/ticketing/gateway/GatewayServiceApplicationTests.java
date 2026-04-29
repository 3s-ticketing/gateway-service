package org.ticketing.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test")
@SpringBootTest(properties = {
	"spring.application.name=gateway-service",
	"spring.config.import=optional:configserver:",
	"spring.cloud.config.enabled=false",
	"spring.cloud.config.fail-fast=false",
	"spring.cloud.config.import-check.enabled=false",
	"spring.cloud.bootstrap.enabled=false",
	"spring.cloud.discovery.enabled=false",
	"eureka.client.enabled=false",
	"eureka.client.register-with-eureka=false",
	"eureka.client.fetch-registry=false"
})
class GatewayServiceApplicationTests {

	@Test
	void contextLoads() {
	}

}