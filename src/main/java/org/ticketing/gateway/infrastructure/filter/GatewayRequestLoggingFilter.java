package org.ticketing.gateway.infrastructure.filter;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class GatewayRequestLoggingFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        boolean hasAuth = authHeader != null && !authHeader.isBlank();

        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String routeId = route != null ? route.getId() : "NO_ROUTE_YET";

        log.info(
            "[GW-IN] method={} path={} query={} authPresent={} authLength={} routeId={}",
            request.getMethod(),
            request.getURI().getPath(),
            request.getURI().getQuery(),
            hasAuth,
            hasAuth ? authHeader.length() : 0,
            routeId
        );

        return chain.filter(exchange)
            .doOnSuccess(unused -> {
                Integer status = Optional.ofNullable(exchange.getResponse().getStatusCode())
                    .map(statusCode -> statusCode.value())
                    .orElse(null);

                Route afterRoute = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
                String afterRouteId = afterRoute != null ? afterRoute.getId() : "NO_ROUTE";

                log.info(
                    "[GW-OUT] method={} path={} status={} routeId={}",
                    request.getMethod(),
                    request.getURI().getPath(),
                    status,
                    afterRouteId
                );
            })
            .doOnError(ex -> log.error(
                "[GW-ERROR] method={} path={} message={}",
                request.getMethod(),
                request.getURI().getPath(),
                ex.getMessage(),
                ex
            ));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}