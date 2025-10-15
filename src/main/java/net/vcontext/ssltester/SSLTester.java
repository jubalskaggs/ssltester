package net.vcontext.ssltester;

import javax.xml.namespace.QName;
import jakarta.xml.soap.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;

public class SSLTester {

    public static void main(String[] args) {
        // Check for command-line argument, otherwise use default
        String serviceUrl;
        if (args.length > 0) {
            serviceUrl = args[0];
        } else {
            serviceUrl = "https://www.google.com";
            System.out.println("No URL provided, using default URL.");
        }

        System.out.println("Testing connection to: " + serviceUrl);
        System.out.println("Java Version: " + System.getProperty("java.version"));
        System.out.println("Trust Store: " + System.getProperty("javax.net.ssl.trustStore"));
        System.out.println();

        // First, retrieve and display certificate information
        displayCertificateInfo(serviceUrl);

        try {
            // Create SOAP Connection
            SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
            SOAPConnection soapConnection = soapConnectionFactory.createConnection();

            // Create SOAP Message
            MessageFactory messageFactory = MessageFactory.newInstance();
            SOAPMessage soapMessage = messageFactory.createMessage();

            // This will attempt to connect to the service
            // The actual SOAP call will likely fail (no valid request),
            // but the SSL/TLS handshake will succeed if CA is trusted
            SOAPMessage response = soapConnection.call(soapMessage, serviceUrl);

            System.out.println("SUCCESS: SSL/TLS connection established!");
            System.out.println("The JVM trusts the CA certificate.");

            soapConnection.close();

        } catch (SOAPException e) {
            // Check if this is an SSL/certificate error
            Throwable cause = e.getCause();
            if (cause != null && (cause.toString().contains("PKIX") ||
                                  cause.toString().contains("certificate") ||
                                  cause.toString().contains("SSL"))) {
                System.err.println("FAILED: SSL/Certificate error detected!");
                System.err.println("The JVM does NOT trust the CA certificate.");
                System.err.println("\nError details:");
                e.printStackTrace();
            } else {
                // Other SOAP errors are expected (invalid request, etc.)
                System.out.println("SUCCESS: SSL/TLS connection established!");
                System.out.println("The JVM trusts the CA certificate.");
                System.out.println("\nNote: SOAP call failed (expected), but certificate validation succeeded.");
                System.out.println("Error: " + e.getMessage());
            }
        } catch (Exception e) {
            System.err.println("Unexpected error:");
            e.printStackTrace();
        }
    }

    private static void displayCertificateInfo(String urlString) {
        try {
            URL url = new URL(urlString);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.connect();

            Certificate[] certs = conn.getServerCertificates();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");

            System.out.println("=== Certificate Information ===");
            System.out.println();

            for (int i = 0; i < certs.length; i++) {
                if (certs[i] instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certs[i];

                    if (i == 0) {
                        System.out.println("Server Certificate:");
                    } else {
                        System.out.println("\nIntermediate/Root Certificate #" + i + ":");
                    }

                    System.out.println("  Subject: " + cert.getSubjectX500Principal().getName());
                    System.out.println("  Issuer:  " + cert.getIssuerX500Principal().getName());
                    System.out.println("  Valid From: " + dateFormat.format(cert.getNotBefore()));
                    System.out.println("  Valid Until: " + dateFormat.format(cert.getNotAfter()));
                    System.out.println("  Serial Number: " + cert.getSerialNumber().toString(16));
                    System.out.println("  Signature Algorithm: " + cert.getSigAlgName());
                }
            }

            System.out.println();
            System.out.println("=== End Certificate Information ===");
            System.out.println();

            conn.disconnect();

        } catch (SSLPeerUnverifiedException e) {
            System.err.println("ERROR: Could not verify SSL certificate");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("ERROR: Could not retrieve certificate information");
            e.printStackTrace();
        }
    }
}
