package com.example.gateway.config;

import com.example.gateway.security.DPoPJwtServerAuthenticationConverter;
import com.example.gateway.security.DpopJwtReactiveAuthenticationManager;
import org.springframework.cloud.gateway.config.GlobalCorsProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final AuthProperties authProperties;

    public SecurityConfig(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }


    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                     GlobalCorsProperties corsProperties) {

        return http

                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(corsSpec -> corsSpec.configurationSource(unused -> corsProperties.getCorsConfigurations().get("/**")))

                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.POST, "/actuator").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oAuth2ResourceServerSpec ->
                        oAuth2ResourceServerSpec
                        .jwt(jwtSpec -> {
                            jwtSpec.jwtDecoder(withProviderConfiguration());
                            jwtSpec.authenticationManager(dPopAuthenticationManager());
                        })
                        .bearerTokenConverter(serverAuthenticationConverter()))

                .build();

    }

    private ReactiveAuthenticationManager dPopAuthenticationManager() {
        return new DpopJwtReactiveAuthenticationManager(withProviderConfiguration());
    }


    private ServerAuthenticationConverter serverAuthenticationConverter() {
        return new DPoPJwtServerAuthenticationConverter();
    }

//    private ReactiveJwtDecoder dPopDecoder() {
//        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
//                .jwtProcessorCustomizer(ReactiveJwtDecoderProviderConfigurationUtils::addJWSAlgorithms)
//                .build();
//        jwtDecoder.setJwtValidator(jwtValidator);
//        return ReactiveJwtDecoders
//                .fromIssuerLocation(authProperties.getIssuerUri());
//    }

    private ReactiveJwtDecoder withProviderConfiguration() {
//        var issuer = authProperties.getIssuerUri();
//        OAuth2TokenValidator<DPopAuthenticationToken> jwtValidator = createDefaultWithIssuer(issuer);
//        NimbusReactiveJwtDecoder jwtDecoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer)
//                .build();
//        OAuth2TokenValidator<Jwt> dpopJwtsValidator= new DPoPTokenValidator();
//        jwtDecoder.setJwtValidator(jwtValidator);
//        return jwtDecoder;
        return ReactiveJwtDecoders
                .fromIssuerLocation(authProperties.getIssuerUri());
    }
//    public OAuth2TokenValidator<DPopAuthenticationToken> createDefaultWithIssuer(String issuer) {
//        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
//        validators.add(new JwtTimestampValidator());
//        validators.add(new JwtIssuerValidator(issuer));
//        var authTokenValidator= new DelegatingOAuth2TokenValidator<>(validators);
//
//        OAuth2TokenValidator<DPopAuthenticationToken> dPopTokenValidator= new DPoPTokenValidator();
//
////        return new DelegatingOAuth2TokenValidator<>(authTokenValidator,dPopTokenValidator);
//
//        return dPopTokenValidator;
//
//    }


}
