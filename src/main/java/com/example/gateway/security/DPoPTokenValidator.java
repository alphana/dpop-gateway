package com.example.gateway.security;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Instant;
import java.util.Date;

public class DPoPTokenValidator {


    public Mono<OAuth2TokenValidatorResult> validate(DPopAuthenticationToken dpopToken, Jwt accessToken) {
        return Mono.fromCallable(() -> {
                    if (!StringUtils.hasText(dpopToken.getAuthzToken())
                        &&
                        !StringUtils.hasText(dpopToken.getDpopTokens())
                    ) {
                        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_dpop_proof",
                                "DPoP proof is missing", null));
                    }

                    SignedJWT dpopJwt = SignedJWT.parse(dpopToken.getDpopTokens());

                    validateDPoPClaims(dpopJwt, accessToken, dpopToken.getMethod(), dpopToken.getUri());

                    // Verify DPoP signature
                    JWSHeader header = dpopJwt.getHeader();
                    ECKey publicKey = ECKey.parse(header.getJWK().toString());
                    if (!dpopJwt.verify(new ECDSAVerifier(publicKey))) {
                        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_dpop_proof",
                                "DPoP proof signature verification failed", null));
                    }

                    return OAuth2TokenValidatorResult.success();
                })
                .onErrorResume(throwable ->
                        Mono.just(
                                OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_dpop_proof",
                                        "Error validating DPoP proof: " + throwable.getMessage(), null)))
                );


    }

    private void validateDPoPClaims(SignedJWT dpopJwt, Jwt accessToken, HttpMethod method, URI uri) throws Exception {
        var claims = dpopJwt.getJWTClaimsSet();

        // Verify timestamp (max 60 seconds old)
        Date creationTime = claims.getDateClaim("iat");
        if (creationTime == null ||
            Instant.now().minusSeconds(60).isAfter(creationTime.toInstant())) {
            throw new IllegalArgumentException("DPoP token has expired or iat is missing");
        }

        // Verify JWT type
        if (!"dpop+jwt".equals(dpopJwt.getHeader().getType().toString())) {
            throw new IllegalArgumentException("Invalid token type");
        }

        // Verify htm (HTTP method)
        if (!method.name().equalsIgnoreCase(claims.getStringClaim("htm"))) {
            throw new IllegalArgumentException("HTTP method mismatch");
        }

        // Verify htu (HTTP URI)
        if (!uri.toString().equalsIgnoreCase(claims.getStringClaim("htu"))) {
            throw new IllegalArgumentException("URI mismatch");
        }

        // Verify jti (unique identifier)
        if (claims.getJWTID() == null) {
            throw new IllegalArgumentException("Missing jti claim");
        }

        // Verify ath (access token hash) if present
        String ath = claims.getStringClaim("ath");
        if (ath != null && !validateAccessTokenHash(ath, accessToken)) {
            throw new IllegalArgumentException("Access token hash mismatch");
        }
    }

    private boolean validateAccessTokenHash(String ath, Jwt accessToken) {
        // Implementation of access token hash validation
        // and compare it with the ath claim
        // developer don't know how to compare those
        return true;
    }
}