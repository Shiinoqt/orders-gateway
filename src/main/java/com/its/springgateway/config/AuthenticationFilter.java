package com.its.springgateway.config;

import com.its.springgateway.utility.GatewayJwt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Validates JWT tokens and forwards authenticated user data as request headers.
 */
@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private final GatewayJwt gatewayJwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/actuator/health");
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String token = parseJwt(request);

        if (token == null) {
            unauthorized(response, "Missing token");
            SecurityContextHolder.clearContext();
            return;
        }

        if (!gatewayJwtUtil.isTokenValid(token)) {
            unauthorized(response, "Invalid token");
            SecurityContextHolder.clearContext();
            return;
        }

        String subject = gatewayJwtUtil.extractSubject(token);
        String username = gatewayJwtUtil.extractUsername(token);
        String email = gatewayJwtUtil.extractEmail(token);
        List<String> roles = gatewayJwtUtil.extractRoles(token);

        if (!StringUtils.hasText(email)) {
            unauthorized(response, "Token does not contain email claim");
            SecurityContextHolder.clearContext();
            return;
        }

        List<SimpleGrantedAuthority> authorities = roles == null
                ? List.of()
                : roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(subject, null, authorities)
        );

        Map<String, String> customHeaders = new HashMap<>();
        customHeaders.put("Auth-User-Id", subject);
        customHeaders.put("Auth-Username", username);
        customHeaders.put("Auth-Email", email);
        customHeaders.put("Auth-Roles", roles != null ? String.join(",", roles) : "");

        HttpServletRequestWrapper wrappedRequest = new HttpServletRequestWrapper(request) {
            @Override
            public String getHeader(String name) {
                String value = customHeaders.get(name);
                return value != null ? value : super.getHeader(name);
            }

            @Override
            public Enumeration<String> getHeaders(String name) {
                String value = customHeaders.get(name);
                if (value != null) {
                    return Collections.enumeration(List.of(value));
                }
                return super.getHeaders(name);
            }

            @Override
            public Enumeration<String> getHeaderNames() {
                Set<String> headerNames = new HashSet<>(customHeaders.keySet());
                Enumeration<String> original = super.getHeaderNames();
                while (original.hasMoreElements()) {
                    headerNames.add(original.nextElement());
                }
                return Collections.enumeration(headerNames);
            }
        };

        filterChain.doFilter(wrappedRequest, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("""
            {"error":"unauthorized","message":"%s"}
            """.formatted(message));
    }
}