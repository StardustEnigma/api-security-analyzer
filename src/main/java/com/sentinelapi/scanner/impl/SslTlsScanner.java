package com.sentinelapi.scanner.impl;

import com.sentinelapi.dto.Vulnerability;
import com.sentinelapi.model.Severity;
import com.sentinelapi.scanner.SecurityScanner;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Slf4j
@Component
public class SslTlsScanner implements SecurityScanner {

    private static final Set<String> WEAK_PROTOCOLS = Set.of("TLSv1", "TLSv1.1", "SSLv3", "SSLv2");
    private static final Set<String> WEAK_CIPHER_PATTERNS = Set.of(
            "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"
    );

    @Override
    public String getName() {
        return "SSL/TLS Scanner";
    }

    @Override
    public List<Vulnerability> scan(String targetUrl) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        URI uri;
        try {
            uri = URI.create(targetUrl);
        } catch (Exception e) {
            return vulnerabilities;
        }

        // Only scan HTTPS targets
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            vulnerabilities.add(Vulnerability.builder()
                    .name("No HTTPS")
                    .severity(Severity.HIGH)
                    .description("The target URL uses plain HTTP without encryption. "
                            + "All data is transmitted in cleartext and can be intercepted.")
                    .evidence("Scheme: " + uri.getScheme())
                    .remediation("Enable HTTPS with a valid TLS certificate. "
                            + "Redirect all HTTP traffic to HTTPS.")
                    .build());
            return vulnerabilities;
        }

        String host = uri.getHost();
        int port = uri.getPort() > 0 ? uri.getPort() : 443;

        try {
            // Create trust-all context for inspection
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String type) {}
                        public void checkServerTrusted(X509Certificate[] certs, String type) {}
                    }
            };

            SSLContext sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(null, trustAll, new java.security.SecureRandom());

            SSLSocketFactory factory = sslCtx.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(10000);
                socket.startHandshake();

                SSLSession session = socket.getSession();

                // Check protocol version
                String protocol = session.getProtocol();
                if (WEAK_PROTOCOLS.contains(protocol)) {
                    vulnerabilities.add(Vulnerability.builder()
                            .name("Weak TLS Protocol: " + protocol)
                            .severity(Severity.HIGH)
                            .description("The server negotiated " + protocol + " which has known vulnerabilities.")
                            .evidence("Negotiated protocol: " + protocol)
                            .remediation("Disable " + protocol + ". Use TLS 1.2 or TLS 1.3 only.")
                            .build());
                }

                // Check cipher suite
                String cipher = session.getCipherSuite();
                for (String weakPattern : WEAK_CIPHER_PATTERNS) {
                    if (cipher.toUpperCase().contains(weakPattern)) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("Weak Cipher Suite")
                                .severity(Severity.MEDIUM)
                                .description("The server uses a weak cipher suite containing " + weakPattern + ".")
                                .evidence("Cipher suite: " + cipher)
                                .remediation("Disable weak cipher suites. Use AEAD ciphers like AES-GCM or ChaCha20.")
                                .build());
                        break;
                    }
                }

                // Check certificate
                Certificate[] certs = session.getPeerCertificates();
                if (certs.length > 0 && certs[0] instanceof X509Certificate x509) {
                    Date notAfter = x509.getNotAfter();
                    Date notBefore = x509.getNotBefore();
                    Date now = new Date();

                    if (now.after(notAfter)) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("Expired SSL Certificate")
                                .severity(Severity.CRITICAL)
                                .description("The server's SSL certificate has expired.")
                                .evidence("Certificate expired on: " + notAfter)
                                .remediation("Renew the SSL certificate immediately.")
                                .build());
                    } else if (notAfter.toInstant().isBefore(Instant.now().plus(30, ChronoUnit.DAYS))) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("SSL Certificate Expiring Soon")
                                .severity(Severity.MEDIUM)
                                .description("The server's SSL certificate will expire within 30 days.")
                                .evidence("Certificate expires on: " + notAfter)
                                .remediation("Renew the SSL certificate before expiration.")
                                .build());
                    }

                    if (now.before(notBefore)) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("SSL Certificate Not Yet Valid")
                                .severity(Severity.HIGH)
                                .description("The server's SSL certificate is not yet valid.")
                                .evidence("Certificate valid from: " + notBefore)
                                .remediation("Check the certificate's validity dates and server clock.")
                                .build());
                    }

                    // Check hostname match
                    try {
                        HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session);
                    } catch (Exception e) {
                        vulnerabilities.add(Vulnerability.builder()
                                .name("SSL Certificate Hostname Mismatch")
                                .severity(Severity.HIGH)
                                .description("The SSL certificate's subject does not match the server hostname.")
                                .evidence("Host: " + host + " | Certificate Subject: " + x509.getSubjectX500Principal())
                                .remediation("Obtain a certificate that matches the server's hostname.")
                                .build());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("SSL/TLS scan failed for {}: {}", targetUrl, e.getMessage());
            vulnerabilities.add(Vulnerability.builder()
                    .name("SSL/TLS Connection Error")
                    .severity(Severity.INFO)
                    .description("Could not establish SSL/TLS connection to inspect the certificate and protocol.")
                    .evidence("Error: " + e.getMessage())
                    .remediation("Verify the server is reachable and properly configured for HTTPS.")
                    .build());
        }

        return vulnerabilities;
    }
}

