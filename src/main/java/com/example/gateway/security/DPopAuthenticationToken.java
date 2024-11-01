package com.example.gateway.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import reactor.util.function.Tuple2;

import java.util.Collections;

public class DPopTokenAuthenticationToken extends AbstractAuthenticationToken {
    private final Tuple2<String, String> tokenTuple;

    public DPopTokenAuthenticationToken(Tuple2<String, String> tokenTuple) {
        super(Collections.emptyList());
        this.tokenTuple = tokenTuple;
    }

    public String getAuthzToken() {
        return this.tokenTuple.getT1();
    }
    public String getDpopTokens() {
        return this.tokenTuple.getT2();
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
