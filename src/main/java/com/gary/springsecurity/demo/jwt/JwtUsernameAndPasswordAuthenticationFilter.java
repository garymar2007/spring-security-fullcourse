package com.gary.springsecurity.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

@Data
@AllArgsConstructor
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final JwtConfig jwtConfig;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        try{
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;
        }catch(IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                 .claim("authorities", authResult.getAuthorities())
                 .setIssuedAt(new Date())
                 .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
                 .signWith(jwtConfig.getSecretKeyForSigning())
                 .compact();
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }
}
