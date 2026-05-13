package org.ticketing.gateway.infrastructure.config;

import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class UserIdInjectionFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_ROLES_HEADER = "X-User-Roles";
    private static final Set<String> SERVICE_ROLES = Set.of("ADMIN", "GENERAL", "CLUB_ADMIN");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
            .cast(JwtAuthenticationToken.class)
            .map(authentication -> {
                String userId = authentication.getToken().getSubject();

                String roles = authentication.getAuthorities()
                    .stream()
                    .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                    .filter(SERVICE_ROLES::contains)
                    .collect(Collectors.joining(","));

                log.info(
                    "[GW-USER-CONTEXT] path={} userId={} roles={}",
                    exchange.getRequest().getURI().getPath(),
                    userId,
                    roles
                );

                ServerHttpRequest mutatedRequest = exchange.getRequest()
                    .mutate()
                    .headers(headers -> {
                        headers.remove(USER_ID_HEADER);
                        headers.remove(USER_ROLES_HEADER);

                        headers.add(USER_ID_HEADER, userId);
                        headers.add(USER_ROLES_HEADER, roles);
                    })
                    .build();

                return exchange.mutate()
                    .request(mutatedRequest)
                    .build();
            })
            .defaultIfEmpty(exchange)
            .flatMap(chain::filter);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}