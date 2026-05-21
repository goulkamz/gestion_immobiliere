package com.immobilier.gestionImmobiliere.server.user.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.security.Key;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class jwtUtils {
    @Value("${jwtSecretAccessKey}")
    private String accessSecret;  // Clé secrète pour signer les access tokens

    @Value("${jwtSecretRefreshKey}")
    private String refreshSecret;  // Clé différente pour les refresh tokens

    @Value("${jwtAccesExpiration:900000}")  // 15 minutes en millisecondes
    private long accessExpiration;

    @Value("${jwtRefreshExpiration:604800000}") // 7 jours
    private long refreshExpiration;

    @Value("${jwt.refresh.cookie.name:refresh_token}")
    private String refreshCookieName;

    @Autowired
    private FingerPrintService fingerprintService;

    @Data
    @Builder
    private static class RefreshTokenData {
        private String username;
        private String fingerprint;
        private Date expiration;
        private boolean used;
        private List<String> roles; // Optionnel
    }

    // Stockage temporaire des refresh tokens valides (en production, utilisez Redis)
    private final Map<String, RefreshTokenData> validRefreshTokens = new ConcurrentHashMap<>();

    // 🔹 GÉNÉRATION ACCESS TOKEN (Bearer)
    public String generateAccessToken(String username, Map<String, Object> extraClaims) {
        Map<String, Object> claims = new HashMap<>(extraClaims);
        claims.put("type", "access");
        claims.put("tokenId", UUID.randomUUID().toString());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessExpiration))
                .signWith(getAccessKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // 🔹 GÉNÉRATION REFRESH TOKEN (Cookie)
    public ResponseCookie generateRefreshTokenCookie(String username, HttpServletRequest request, HttpServletResponse response) {
        String refreshTokenId = UUID.randomUUID().toString();

        String fingerprint = fingerprintService.generateFingerprint(request, response);

        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        claims.put("tokenId", refreshTokenId);
        claims.put("fingerprint", fingerprint); // Sécurité : lie le token au device

        String refreshToken = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .signWith(getRefreshKey(), SignatureAlgorithm.HS256)
                .compact();

        // Stocker pour vérification et rotation
        validRefreshTokens.put(refreshTokenId, RefreshTokenData.builder()
                .username(username)
                .fingerprint(fingerprint)
                .expiration(new Date(System.currentTimeMillis() + refreshExpiration))
                .used(false)
                .build());

        // Cookie httpOnly + Secure + SameSite=Strict
        return ResponseCookie.from(refreshCookieName, refreshToken)
                .httpOnly(true)          // ← Protège contre XSS
                .secure(true)            // ← HTTPS uniquement
                .sameSite("Strict")      // ← Protège contre CSRF
                .path("/")
                .maxAge(refreshExpiration / 1000)
                .build();
    }

    // 🔹 EXTRACTION DES TOKENS (Web + Mobile)
    public String extractAccessToken(HttpServletRequest request) {
        // 1. D'abord chercher dans header (mobile + web)
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // 2. Sinon chercher dans cookie (fallback pour web legacy)
        Cookie cookie = WebUtils.getCookie(request, "access_token");
        if (cookie != null) {
            return cookie.getValue();
        }

        return null;
    }

    public String extractRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, refreshCookieName);
        return cookie != null ? cookie.getValue() : null;
    }

    // 🔹 VALIDATION DES TOKENS
    public boolean validateAccessToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getAccessKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Vérifier que c'est bien un access token
            return "access".equals(claims.get("type"));
        } catch (Exception e) {
            log.error("Access token invalide: {}", e.getMessage());
            return false;
        }
    }

    public boolean validateRefreshToken(String token, String expectedFingerprint) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getRefreshKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Vérifier le type
            if (!"refresh".equals(claims.get("type"))) {
                return false;
            }

            // Vérifier le fingerprint (anti-vol)
            String tokenFingerprint = (String) claims.get("fingerprint");
            if (!expectedFingerprint.equals(tokenFingerprint)) {
                log.warn("Fingerprint mismatch - possible vol de token");
                return false;
            }

            // Vérifier dans le store
            String tokenId = (String) claims.get("tokenId");
            RefreshTokenData storedToken = validRefreshTokens.get(tokenId);

            if (storedToken == null || storedToken.isUsed()) {
                log.warn("Refresh token déjà utilisé ou inexistant");
                return false;
            }

            return true;
        } catch (Exception e) {
            log.error("Refresh token invalide: {}", e.getMessage());
            return false;
        }
    }

    // 🔹 ROTATION DU REFRESH TOKEN (sécurité maximale)
    public Map<String, Object> refreshTokens(String oldRefreshToken, String fingerprint, HttpServletRequest request,HttpServletResponse response) {
        if (!validateRefreshToken(oldRefreshToken, fingerprint)) {
            throw new SecurityException("Refresh token invalide");
        }

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getRefreshKey())
                .build()
                .parseClaimsJws(oldRefreshToken)
                .getBody();

        String username = claims.getSubject();
        String oldTokenId = (String) claims.get("tokenId");

        // Marquer l'ancien token comme utilisé (rotation)
        RefreshTokenData oldToken = validRefreshTokens.get(oldTokenId);
        if (oldToken != null) {
            oldToken.setUsed(true);
        }

        // Générer nouveau fingerprint (user-agent + IP)
        String newFingerprint = generateFingerprint(request);

        // Générer nouveau refresh token + cookie
        ResponseCookie newRefreshCookie = generateRefreshTokenCookie(username, request,response);

        // Générer nouvel access token
        Map<String, Object> accessClaims = new HashMap<>();
        accessClaims.put("roles", oldToken.getRoles()); // À adapter
        String newAccessToken = generateAccessToken(username, accessClaims);

        return Map.of(
                "accessToken", newAccessToken,
                "refreshCookie", newRefreshCookie
        );
    }

    // 🔹 FINGERPRINT (anti-vol de token)
    private String generateFingerprint(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String ip = request.getRemoteAddr();
        return UUID.nameUUIDFromBytes((userAgent + ip).getBytes()).toString();
    }

    // 🔹 NETTOYAGE REFRESH TOKEN (logout)
    public ResponseCookie revokeRefreshToken(String refreshToken) {
        if (refreshToken != null) {
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(getRefreshKey())
                        .build()
                        .parseClaimsJws(refreshToken)
                        .getBody();

                String tokenId = (String) claims.get("tokenId");
                validRefreshTokens.remove(tokenId);
            } catch (Exception e) {
                log.warn("Token déjà invalide lors du logout");
            }
        }

        return ResponseCookie.from(refreshCookieName, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build();
    }

    private Key getAccessKey() {
        byte[] keyBytes = Decoders.BASE64.decode(accessSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    private Key getRefreshKey() {
        byte[] keyBytes = Decoders.BASE64.decode(refreshSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
