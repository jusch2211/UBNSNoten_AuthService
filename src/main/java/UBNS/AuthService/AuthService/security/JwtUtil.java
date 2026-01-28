package UBNS.AuthService.AuthService.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import UBNS.AuthService.AuthService.model.AppUser;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String jwtSecret="super-geheimes-jwt-secret-123super-geheimes-jwt-secret-123super-geheimes-jwt-secret-123super-geheimes-jwt-secret-123";
    private final Key key =
            Keys.hmacShaKeyFor(jwtSecret.getBytes());

    private final long expirationMs = 60 * 60 * 1000; // 1 Stunde

    public String generateToken(AppUser user) {
        return Jwts.builder()
                .setSubject(user.username())
                .claim("role", user.role())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
