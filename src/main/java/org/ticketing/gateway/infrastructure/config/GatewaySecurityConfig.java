package org.ticketing.gateway.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@Profile("!test")
public class GatewaySecurityConfig {

    // MVP 통합 테스트용 임시 SecurityConfig
    // Gateway에서 먼저 401/403이 발생하지 않도록 전체 요청 허용
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .authorizeExchange(exchange -> exchange
                .anyExchange().permitAll()
            )
            .build();
    }
}