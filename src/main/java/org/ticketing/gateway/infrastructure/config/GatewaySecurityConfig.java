package org.ticketing.gateway.infrastructure.config;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

@Slf4j
@Configuration
public class GatewaySecurityConfig {

    private static final Set<String> SERVICE_ROLES = Set.of("ADMIN", "GENERAL", "CLUB_ADMIN");

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authorizeExchange(exchange -> exchange
                // Actuator / Error
                .pathMatchers(
                    "/actuator/health",
                    "/actuator/info",
                    "/error",
                    "/actuator/**"
                ).permitAll()

                // Internal API는 외부 Gateway 경유 요청 차단
                .pathMatchers("/internal/**").denyAll()

                // Public API
                .pathMatchers(HttpMethod.POST, "/api/users").permitAll()
                .pathMatchers("/api/auth/**").permitAll()

                // User
                .pathMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/users/*/status").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/users/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/users/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/users/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")

                // Club
                .pathMatchers(HttpMethod.POST, "/api/clubs").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/clubs/*/name").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/clubs/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/clubs/*/admin").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/clubs/*/stadiums").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/clubs/*/stadiums/*").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/clubs").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/clubs/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")

                // Stadium
                .pathMatchers(HttpMethod.POST, "/api/stadiums").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/stadiums/*").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/stadiums/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/stadiums").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/stadiums/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")

                // Seat
                .pathMatchers(HttpMethod.POST, "/api/seats").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/seats/bulk").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/seats/*/grade").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/seats/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/seats/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")

                // SeatGrade
                .pathMatchers(HttpMethod.POST, "/api/seat-grades").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/seat-grades/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/seat-grades/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/seat-grades/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")

                // Match
                .pathMatchers(HttpMethod.GET, "/api/matches").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/matches/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/matches").hasRole("CLUB_ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/matches/").hasRole("CLUB_ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/matches/*/status").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/matches/*").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/matches/*").hasRole("ADMIN")

                // Zone Policy
                .pathMatchers(HttpMethod.GET, "/api/matches/*/zone-policies").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/matches/*/zone-policies").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.PATCH, "/api/matches/*/zone-policies/*").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/matches/*/zone-policies/*").hasAnyRole("ADMIN", "CLUB_ADMIN")

                // Reservation / Ticket
                .pathMatchers(HttpMethod.POST, "/api/reservations").hasRole("GENERAL")
                .pathMatchers(HttpMethod.GET, "/api/reservations").hasAnyRole("ADMIN", "GENERAL")
                .pathMatchers(HttpMethod.GET, "/api/reservations/*/tickets").hasAnyRole("ADMIN", "GENERAL")
                .pathMatchers(HttpMethod.GET, "/api/reservations/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/reservations/*").hasAnyRole("ADMIN", "GENERAL")
                .pathMatchers(HttpMethod.GET, "/api/tickets/*").hasAnyRole("ADMIN", "GENERAL")
                .pathMatchers(HttpMethod.PATCH, "/api/tickets/*/use").hasAnyRole("ADMIN", "CLUB_ADMIN")

                // Queue
                .pathMatchers(HttpMethod.POST, "/api/queues/*/entry").authenticated()
                .pathMatchers(HttpMethod.GET, "/api/queues/*/status").authenticated()
                .pathMatchers(HttpMethod.POST, "/api/queues/*/validation").authenticated()
                .pathMatchers(HttpMethod.GET, "/api/queues").hasRole("ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/queues/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/queues/*/refresh").hasRole("ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/queues/*/*/banned").hasAnyRole("ADMIN", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.POST, "/api/queues/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.PUT, "/api/queues/*").hasRole("ADMIN")
                .pathMatchers(HttpMethod.DELETE, "/api/queues/*").hasRole("ADMIN")

                // Payment
                .pathMatchers(HttpMethod.POST, "/api/payments").hasRole("GENERAL")
                .pathMatchers(HttpMethod.POST, "/api/payments/success").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/payments/webhook").permitAll()
                .pathMatchers(HttpMethod.POST, "/api/payments/refund/reservations/*").denyAll()
                .pathMatchers(HttpMethod.GET, "/api/payments/my/**").hasRole("GENERAL")
                .pathMatchers(HttpMethod.GET, "/api/payments/reservations/*").hasAnyRole("ADMIN", "GENERAL", "CLUB_ADMIN")
                .pathMatchers(HttpMethod.GET, "/api/payments/*").hasAnyRole("ADMIN", "CLUB_ADMIN")

                // Fallback
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
                log.warn("[GW-AUTH] realm_access.roles is empty. subject={}", jwt.getSubject());
                return Flux.empty();
            }

            @SuppressWarnings("unchecked")
            Collection<String> roles = (Collection<String>) realmAccess.get("roles");

            log.info("[GW-AUTH] subject={} rawRoles={}", jwt.getSubject(), roles);

            return Flux.fromIterable(roles)
                .map(role -> role.startsWith("ROLE_") ? role.substring(5) : role)
                .filter(SERVICE_ROLES::contains)
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .doOnNext(authority ->
                    log.info("[GW-AUTHORITY] subject={} authority={}", jwt.getSubject(), authority.getAuthority())
                );
        });

        return converter;
    }
}