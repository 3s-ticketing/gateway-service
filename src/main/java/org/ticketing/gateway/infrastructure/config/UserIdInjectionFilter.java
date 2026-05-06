package org.ticketing.gateway.infrastructure.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class UserIdInjectionFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
            .cast(JwtAuthenticationToken.class)
            .map(authentication -> {
                String userId = authentication.getToken().getSubject();

                ServerHttpRequest mutatedRequest = exchange.getRequest()
                    .mutate()
                    .headers(headers -> {
                        headers.remove(USER_ID_HEADER);
                        headers.add(USER_ID_HEADER, userId);
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