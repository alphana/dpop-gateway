package com.example.gateway.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import reactor.util.function.Tuple2;

import java.net.URI;
import java.util.Collections;

public class DPopAuthenticationToken extends AbstractAuthenticationToken {
    private final Tuple2<String, String> tokenTuple;


    private final HttpMethod method;
    private final URI uri;

    public DPopAuthenticationToken(HttpMethod method, URI uri, Tuple2<String, String> tokens) {
        super(Collections.emptyList());
        this.tokenTuple = tokens;
        this.method = method;
        this.uri = uri;
    }

    public String getAuthzToken() {
        return this.tokenTuple.getT1();
    }

    public String getDpopTokens() {
        return this.tokenTuple.getT2();
    }

    public HttpMethod getMethod() {
        return method;
    }

    public URI getUri() {
        return uri;
    }

    @Override
    public Object getCredentials() {
        return this.tokenTuple;
    }

    @Override
    public Object getPrincipal() {
        return this.tokenTuple;
    }
}
