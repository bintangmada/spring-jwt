package com.bintang.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
public class JwtService {

    private final String secretKey;
    public JwtService(@Value("${jwt.secret}") String secretKey){
        this.secretKey = secretKey;
    }

    public String extractUsername(String token){
        return getClaims(token).getSubject();
    }

    private Claims getClaims(String token){
        return Jwts
                .parser()
                .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean isTokenValid(String token){
        try{
            getClaims(token);
            return true;
        }catch (Exception e){
            return false;
        }
    }

}
