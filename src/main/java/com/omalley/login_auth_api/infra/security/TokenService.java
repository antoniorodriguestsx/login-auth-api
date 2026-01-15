package com.omalley.login_auth_api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.omalley.login_auth_api.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create().withIssuer("login-auth-api").withSubject(user.getEmail()).withExpiresAt(generateExpirationDate()).sign(algorithm);
        }
        catch (JWTCreationException exception) {
            throw new RuntimeException("Error while authenticating");
        }
    }

    public String validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm).build().verify(token).getSubject();
        }
        catch(JWTVerificationException exception) {
            return null;
        }
    }

    public long getRemainingTimeInSeconds(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            DecodedJWT decodedJWT = JWT.require(algorithm)
                    .build()
                    .verify(token);

            Instant expiresAt = decodedJWT.getExpiresAt().toInstant();
            Instant now = Instant.now();

            long remainingSeconds = Duration.between(now, expiresAt).getSeconds();

            return remainingSeconds > 0 ? remainingSeconds : -1;
        }
        catch(JWTVerificationException exception) {
            return -1;
        }
    }

    private Instant generateExpirationDate() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-3"));
    }
}
