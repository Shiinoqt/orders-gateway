package com.its.springgateway.utility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

/**
 * Utility for validating and extracting claims from JWT tokens.
 *
 * <p>Claims are expected to include: subject, username, email, and roles.</p>
 */
@Component
public class GatewayJwt {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Checks if the token is not expired.
     *
     * @param token JWT string
     * @return true if the token is valid and not expired
     */
    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts the subject (typically user ID) from the token.
     *
     * @param token JWT string
     * @return subject claim
     */
    public String extractSubject(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Extracts the custom username claim from the token.
     *
     * @param token JWT string
     * @return username claim
     */
    public String extractUsername(String token) {
        return extractAllClaims(token).get("username", String.class);
    }

    /**
     * Extracts the email claim from the token.
     *
     * @param token JWT string
     * @return email claim, or null if not present
     */
    public String extractEmail(String token) {
        return extractAllClaims(token).get("email", String.class);
    }

    /**
     * Extracts the roles claim from the token.
     *
     * @param token JWT string
     * @return list of roles, or null if not present
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }
}