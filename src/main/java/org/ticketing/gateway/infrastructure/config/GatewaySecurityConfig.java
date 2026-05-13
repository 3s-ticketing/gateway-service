package org.ticketing.gateway.infrastructure.config;

import java.util.Collection;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

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
                    "/actuator/**"
                ).permitAll()

                // 회원가입은 인증 없이 허용
                .pathMatchers(HttpMethod.POST, "/api/users").permitAll()

                // 현재 로그인/토큰 관련 API는 허용
                .pathMatchers("/api/auth/**").permitAll()

                // 클럽 관리자 가입 승인/거절은 ADMIN만 허용
                .pathMatchers(HttpMethod.PATCH, "/api/users/*/status").hasRole("ADMIN")

                // 그 외 요청은 인증 필요
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
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .build();
    }

    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");

            if (realmAccess == null || realmAccess.get("roles") == null) {
                return Flux.empty();
            }

            @SuppressWarnings("unchecked")
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");

            return Flux.fromIterable(roles)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role));
        });

        return converter;
    }
}