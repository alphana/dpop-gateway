package com.example.gateway.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;

import java.util.Collection;

public class DpopJwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private final ReactiveJwtDecoder jwtDecoder;
    private final DPoPTokenValidator validator;

    private final Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverterAdapter(
            new JwtAuthenticationConverter());

    public DpopJwtReactiveAuthenticationManager(ReactiveJwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
        this.validator = new DPoPTokenValidator();
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        return Mono.justOrEmpty(authentication)
                .filter((a) -> a instanceof DPopAuthenticationToken)
                .cast(DPopAuthenticationToken.class)
                .map(dPopToken ->
                        Mono.zip(jwtDecoder.decode(dPopToken.getAuthzToken()), Mono.just(dPopToken))
                )
                .flatMap(this::validate)
                .flatMap(this.jwtAuthenticationConverter::convert)
                .cast(Authentication.class)
                .onErrorMap(JwtException.class, this::onError);

    }

    private Mono<Jwt> validate(Mono<Tuple2<Jwt, DPopAuthenticationToken>> tuple2Mono) {
        return tuple2Mono
                .flatMap(tuple -> validator.validate(tuple.getT2(), tuple.getT1()))
                .flatMap(result -> {
                    if (result.hasErrors()) {
                        Collection<OAuth2Error> errors = result.getErrors();
                        String validationErrorString = getJwtValidationExceptionMessage(errors);
                        return Mono.error(new JwtValidationException(validationErrorString, errors));
                    }

                    return tuple2Mono.map(Tuple2::getT1);
                });


    }


    private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
        for (OAuth2Error oAuth2Error : errors) {
            if (StringUtils.hasLength(oAuth2Error.getDescription())) {
                return oAuth2Error.getDescription();
            }
        }
        return "Unable to validate DPop";
    }

    private AuthenticationException onError(JwtException ex) {
        if (ex instanceof BadJwtException) {
            return new InvalidBearerTokenException(ex.getMessage(), ex);
        }
        return new AuthenticationServiceException(ex.getMessage(), ex);
    }
}
