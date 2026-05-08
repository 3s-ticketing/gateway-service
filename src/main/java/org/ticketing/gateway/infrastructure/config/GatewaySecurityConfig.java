package org.ticketing.gateway.infrastructure.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Slf4j
@Configuration
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchange -> exchange
                .pathMatchers(
                    "/actuator/health",
                    "/actuator/info",
                    "/error",
                    "/api/users",
                    "/api/auth/**",
                    "/actuator/**"
                ).permitAll()
                .anyExchange().authenticated()
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((exchange, ex) -> {
                    log.warn(
                        "[GW-401] path={} reason={}",
                        exchange.getRequest().getURI().getPath(),
                        ex.getMessage()
                    );

                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                })
                .accessDeniedHandler((exchange, ex) -> {
                    log.warn(
                        "[GW-403] path={} reason={}",
                        exchange.getRequest().getURI().getPath(),
                        ex.getMessage()
                    );

                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                })
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .build();
    }
}