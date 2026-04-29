package org.ticketing.gateway.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@Profile("!test")
public class GatewaySecurityConfig {

    private static final String[] PERMIT_ALL_PATHS = {
        "/actuator/health",
        "/actuator/info",
        "/error"
    };

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .authorizeExchange(exchange -> exchange
                .pathMatchers(PERMIT_ALL_PATHS).permitAll()

                // 회원가입
                .pathMatchers(HttpMethod.POST, "/api/users").permitAll()

                // 로그인
                .pathMatchers(HttpMethod.POST, "/api/auth/login").permitAll()

                // 그 외 요청은 인증 필요
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
            )
            .build();
    }
}