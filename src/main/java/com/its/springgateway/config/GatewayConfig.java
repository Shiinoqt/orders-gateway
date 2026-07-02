package com.its.springgateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.predicate.GatewayRequestPredicates.path;

/**
 * Route configuration for the gateway.
 * <p>
 * Auth header injection (Auth-User-Id, Auth-Username, Auth-Email, Auth-Roles) is
 * handled exclusively by {@link AuthenticationFilter}, which runs earlier in the
 * servlet filter chain, validates the JWT, and rejects unauthenticated requests.
 * Routes here must NOT add auth headers again, since ServerRequest.Builder#header
 * appends rather than replaces, which previously caused duplicated header values
 * (e.g. Auth-User-Id arriving downstream twice).
 */
@Configuration
public class GatewayConfig {

    @Value("${orders.uri}")
    private String ordersUri;

    @Value("${payments.uri}")
    private String paymentsUri;

    private RouterFunction<ServerResponse> buildRoute(String id, String pathPrefix, String targetUri) {
        return GatewayRouterFunctions.route(id)
                .route(path(pathPrefix).or(path(pathPrefix + "/**")), HandlerFunctions.http())
                .before(uri(URI.create(targetUri)))
                .build();
    }

    @Bean
    public RouterFunction<ServerResponse> orderRoute() {
        return buildRoute("order-service", "/api/orders", ordersUri);
    }

    @Bean
    public RouterFunction<ServerResponse> paymentRoute() {
        return buildRoute("payment-service", "/api/payments", paymentsUri);
    }
}