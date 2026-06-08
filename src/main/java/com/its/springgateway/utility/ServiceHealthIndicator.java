package com.its.springgateway.utility;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class ServiceHealthIndicator implements HealthIndicator {

    @Value("${orders.uri}")
    private String ordersUri;

    @Value("${payments.uri}")
    private String paymentsUri;

    @Value("${context.path:}")
    private String contextPath;

    private final RestTemplate restTemplate;

    public ServiceHealthIndicator(RestTemplateBuilder builder) {
        this.restTemplate = builder.build();
    }

    @Override
    public Health health() {
        Map<String, Object> details = new LinkedHashMap<>();
        boolean allUp = true;

        // Check orders service
        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(
                    ordersUri + contextPath + "/actuator/health", Map.class
            );
            if (response.getStatusCode().is2xxSuccessful()) {
                details.put("orders-service", "UP");
            } else {
                details.put("orders-service", "DOWN (HTTP " + response.getStatusCode() + ")");
                allUp = false;
            }
        } catch (Exception e) {
            details.put("orders-service", "DOWN - " + e.getMessage());
            allUp = false;
        }

        // Check payments service
        try {
            ResponseEntity<Map> response = restTemplate.getForEntity(
                    paymentsUri + contextPath + "/actuator/health", Map.class
            );
            if (response.getStatusCode().is2xxSuccessful()) {
                details.put("payments-service", "UP");
            } else {
                details.put("payments-service", "DOWN (HTTP " + response.getStatusCode() + ")");
                allUp = false;
            }
        } catch (Exception e) {
            details.put("payments-service", "DOWN - " + e.getMessage());
            allUp = false;
        }

        if (allUp) {
            return Health.up().withDetails(details).build();
        } else {
            return Health.down().withDetails(details).build();
        }
    }
}