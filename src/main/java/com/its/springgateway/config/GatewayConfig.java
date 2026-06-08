package com.its.springgateway.config;

import com.its.springgateway.utility.GatewayJwt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions;
import org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.net.URI;
import java.util.List;
import java.util.function.Function;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.predicate.GatewayRequestPredicates.path;

@Configuration
public class GatewayConfig {

    private final GatewayJwt gatewayJwt;

    public GatewayConfig(GatewayJwt gatewayJwt) {
        this.gatewayJwt = gatewayJwt;
    }

    @Value("${orders.uri}")
    private String ordersUri;

    @Value("${payments.uri}")
    private String paymentsUri;

    private RouterFunction<ServerResponse> buildRoute(String id, String pathPrefix, String targetUri) {
        return GatewayRouterFunctions.route(id)
                .route(path(pathPrefix).or(path(pathPrefix + "/**")), HandlerFunctions.http())
                .before(addAuthHeaders())
                .before(uri(URI.create(targetUri)))
                .build();
    }

    private Function<ServerRequest, ServerRequest> addAuthHeaders() {
        return request -> {
            String authHeader = request.headers().firstHeader("Authorization");

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return request;
            }

            String token = authHeader.substring(7);

            if (!gatewayJwt.isTokenValid(token)) {
                return request;
            }

            String subject = gatewayJwt.extractSubject(token);
            String username = gatewayJwt.extractUsername(token);
            List<String> roles = gatewayJwt.extractRoles(token);
            String rolesHeader = roles != null ? String.join(",", roles) : "";

            return ServerRequest.from(request)
                    .header("Auth-User-Id", subject)
                    .header("Auth-Username", username)
                    .header("Auth-Roles", rolesHeader)
                    .build();
        };
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