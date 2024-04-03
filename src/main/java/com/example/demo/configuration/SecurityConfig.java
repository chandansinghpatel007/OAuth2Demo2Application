package com.example.demo.configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails userDetails=User.withUsername("Chandan")
				.password("{noop}virus")
				.authorities("read")
				.build();
		return new InMemoryUserDetailsManager(userDetails);
	}
	
	@Bean
	@Order(2)
	public SecurityFilterChain userDetailsSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.formLogin(Customizer.withDefaults());
		httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
		return httpSecurity.build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(){
		KeyPair keyPair=generateKeyPair();
		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey=new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet=new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}
	
	private static KeyPair generateKeyPair() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair=keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
		return keyPair;
	}
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
}
