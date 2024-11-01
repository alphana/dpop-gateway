package com.example.gateway.security;


import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class DPoPJwtAuthenticationConverter implements ServerAuthenticationConverter {
    private static final Pattern authorizationPattern = Pattern.compile("^DPoP (?<token>[a-zA-Z0-9-._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern dpopPattern = Pattern.compile("^(?<token>[a-zA-Z0-9-._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);

    public static final String DPOP = "Dpop";



    private Tuple2<String, String> resolveFromAuthorizationHeaders(HttpHeaders headers) {
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (!StringUtils.startsWithIgnoreCase(authorization, "Dpop")) {
            BearerTokenError error = BearerTokenErrors
                    .invalidRequest("Authorization header not Found in the request");
            throw new OAuth2AuthenticationException(error);
        }
        String dPopToken = headers.getFirst(DPOP);
        if (dPopToken == null) {
            BearerTokenError error = BearerTokenErrors
                    .invalidRequest("Dpop header not Found in the request");
            throw new OAuth2AuthenticationException(error);
        }

        Matcher authzTokenMatcher = authorizationPattern.matcher(authorization);
        if (!authzTokenMatcher.matches()) {
            BearerTokenError error = invalidTokenError();
            throw new OAuth2AuthenticationException(error);
        }


        Matcher dpopTokenMatcher = dpopPattern.matcher(dPopToken);
        if (!dpopTokenMatcher.matches()) {
            BearerTokenError error = invalidTokenError();
            throw new OAuth2AuthenticationException(error);
        }

        return Tuples.of(
                authzTokenMatcher.group("token"),
                dpopTokenMatcher.group("token")
        );


    }

    private static BearerTokenError invalidTokenError() {
        return BearerTokenErrors.invalidToken("Dpop token is malformed");
    }



    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> resolveFromAuthorizationHeaders(exchange.getRequest().getHeaders()))
                .map(DPopTokenAuthenticationToken::new);
    }

}