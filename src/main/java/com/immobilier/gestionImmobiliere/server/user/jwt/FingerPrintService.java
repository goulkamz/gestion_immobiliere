package com.immobilier.gestionImmobiliere.server.user.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
    public class FingerPrintService {

        private static final Logger log =  LoggerFactory.getLogger(FingerPrintService.class);

        @Value("${finger.secret.key}")
        private String fingerSecret;
        /**
         * Génère une empreinte unique pour la requête
         */
        public String generateFingerprint(HttpServletRequest request, HttpServletResponse response) {
            FingerprintData data = collectFingerprintData(request, response);
            String fingerprintData = buildFingerprintString(data);

            String fingerprint = UUID.nameUUIDFromBytes(fingerprintData.getBytes()).toString();
            log.debug("Fingerprint généré: {} pour appareil: {}", fingerprint, data.deviceId);

            return fingerprint;
        }

        /**
         * Collecte toutes les données d'empreinte
         */
        private FingerprintData collectFingerprintData(HttpServletRequest request, HttpServletResponse response) {
            FingerprintData data = new FingerprintData();

            // 1. User-Agent (avec nettoyage)
            data.userAgent = cleanUserAgent(request.getHeader("User-Agent"));

            // 2. IP avec gestion proxy
            data.ip = getRealIp(request);

            // 3. Device ID sécurisé
            data.deviceId = getOrCreateSecureDeviceId(request, response);

            // 4. Accept-Language
            data.acceptLanguage = request.getHeader("Accept-Language");

            // 5. Sec-Fetch headers (navigateurs modernes)
            data.secFetchSite = request.getHeader("Sec-Fetch-Site");
            data.secFetchMode = request.getHeader("Sec-Fetch-Mode");

            // 6. Timezone (via cookie ou header)
            data.timezone = request.getHeader("X-Timezone");

            return data;
        }

        /**
         * Construit la chaîne d'empreinte selon le type d'appareil
         */
        private String buildFingerprintString(FingerprintData data) {
            if (isMobile(data.userAgent)) {
                // Mobile : ignorer l'IP
                return String.join("|",
                        data.userAgent != null ? data.userAgent : "unknown",
                        data.deviceId != null ? data.deviceId : "unknown",
                        data.acceptLanguage != null ? data.acceptLanguage : "unknown"
                );
            } else {
                // Web : tout inclure
                return String.join("|",
                        data.userAgent != null ? data.userAgent : "unknown",
                        data.ip != null ? data.ip : "unknown",
                        data.deviceId != null ? data.deviceId : "unknown",
                        data.acceptLanguage != null ? data.acceptLanguage : "unknown",
                        data.secFetchSite != null ? data.secFetchSite : "unknown",
                        data.secFetchMode != null ? data.secFetchMode : "unknown"
                );
            }
        }

        /**
         * Obtient la vraie IP (gère les proxys)
         */
        private String getRealIp(HttpServletRequest request) {
            String[] headers = {"X-Forwarded-For", "X-Real-IP", "Proxy-Client-IP", "WL-Proxy-Client-IP"};

            for (String header : headers) {
                String ip = request.getHeader(header);
                if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                    // X-Forwarded-For peut contenir plusieurs IPs
                    if (header.equals("X-Forwarded-For")) {
                        ip = ip.split(",")[0].trim();
                    }
                    return ip;
                }
            }
            return request.getRemoteAddr();
        }

        /**
         * Device ID sécurisé avec signature
         */
        private String getOrCreateSecureDeviceId(HttpServletRequest request, HttpServletResponse response) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("device_id".equals(cookie.getName())) {
                        String signedDeviceId = cookie.getValue();
                        return validateAndExtractDeviceId(signedDeviceId);
                    }
                }
            }

            // Créer nouveau device ID
            String deviceId = UUID.randomUUID().toString();
            String signedDeviceId = signDeviceId(deviceId);

            // Cookie sécurisé
            Cookie deviceCookie = new Cookie("device_id", signedDeviceId);
            deviceCookie.setHttpOnly(true);
            deviceCookie.setSecure(true);
            deviceCookie.setPath("/");
            deviceCookie.setMaxAge(365 * 24 * 60 * 60); // 1 an
            deviceCookie.setAttribute("SameSite", "Strict");
            response.addCookie(deviceCookie);

            return deviceId;
        }

        /**
         * Signe le device ID pour éviter la falsification
         */
        private String signDeviceId(String deviceId) {
            // Simple HMAC pour vérifier l'intégrité
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                SecretKeySpec secret = new SecretKeySpec(fingerSecret.getBytes(), "HmacSHA256");
                mac.init(secret);
                byte[] signature = mac.doFinal(deviceId.getBytes());
                String signatureB64 = Base64.getEncoder().encodeToString(signature);
                return deviceId + "." + signatureB64;
            } catch (Exception e) {
                return deviceId;
            }
        }

        /**
         * Valide et extrait le device ID signé
         */
        private String validateAndExtractDeviceId(String signedDeviceId) {
            if (!signedDeviceId.contains(".")) {
                return null;  // Cookie falsifié
            }

            String[] parts = signedDeviceId.split("\\.");
            if (parts.length != 2) {
                return null;
            }

            String deviceId = parts[0];
            String providedSignature = parts[1];
            String expectedSignature = signDeviceId(deviceId).split("\\.")[1];

            if (providedSignature.equals(expectedSignature)) {
                return deviceId;  // Valide
            }
            return null;  // Falsifié
        }

        /**
         * Nettoie le User-Agent (enlève les versions pour stabilité)
         */
        private String cleanUserAgent(String userAgent) {
            if (userAgent == null) return null;

            // Enlever les numéros de version pour éviter les changements
            return userAgent
                    .replaceAll("Chrome/[0-9.]+", "Chrome")
                    .replaceAll("Firefox/[0-9.]+", "Firefox")
                    .replaceAll("Safari/[0-9.]+", "Safari")
                    .replaceAll("Version/[0-9.]+", "Version")
                    .replaceAll("Edge/[0-9.]+", "Edge")
                    .replaceAll("rv:[0-9.]+", "rv");
        }

        private boolean isMobile(String userAgent) {
            return userAgent != null &&
                    (userAgent.contains("Android") ||
                            userAgent.contains("iPhone") ||
                            userAgent.contains("iPad") ||
                            userAgent.contains("Mobile"));
        }

        /**
         * Vérifie si deux fingerprints correspondent (avec tolérance)
         */
        public boolean fingerprintsMatch(String storedFingerprint, String currentFingerprint,
                                         HttpServletRequest request) {
            if (storedFingerprint.equals(currentFingerprint)) {
                return true;  // Match parfait
            }

            // Tolérance pour les changements d'IP légitimes
            log.warn("Fingerprint mismatch - Possible token theft or IP change");
            log.warn("Stored: {}, Current: {}", storedFingerprint, currentFingerprint);

            // Enregistrer l'événement de sécurité
            //SecurityEventLogger.logPotentialTheft(request);

            return false;  // Pour haute sécurité, refuser
        }

        // Classe interne pour les données
        @Data
        private static class FingerprintData {
            private String userAgent;
            private String ip;
            private String deviceId;
            private String acceptLanguage;
            private String secFetchSite;
            private String secFetchMode;
            private String timezone;
        }

    @Data
    public static class DeviceInfo {
        private final String deviceId;
        private long firstSeen;
        private long lastSeen;

        public DeviceInfo(String deviceId) {
            this.deviceId = deviceId;
            this.firstSeen = System.currentTimeMillis();
            this.lastSeen = System.currentTimeMillis();
        }

        public void updateLastSeen() {
            this.lastSeen = System.currentTimeMillis();
        }
    }
    }

