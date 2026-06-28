package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"adaptix_listener_open_malleable/openmalleable"
)

func newTestTransport(profileText string) *TransportMalleable {
	profile := openmalleable.NewMalleableProfile(profileText)
	return &TransportMalleable{
		Profile: profile,
		MServer: openmalleable.NewMalleableServer(profile),
	}
}

func TestFindVariantMatchesConfiguredMethod(t *testing.T) {
	transport := newTestTransport(`
http-get {
	set uri "/";
	client {
		metadata {
			base64;
			parameter "id";
		}
	}
	server {
		output {
			print;
		}
	}
}

http-post {
	set uri "/submit";
	client {
		id {
			base64;
			parameter "id";
		}
		output {
			base64;
			print;
		}
	}
	server {
		output {
			print;
		}
	}
}
`)

	if variant := transport.findGetVariant("POST", "/submit"); variant != "" {
		t.Fatalf("POST /submit was misclassified as GET variant %q", variant)
	}
	if variant := transport.findPostVariant("POST", "/submit"); variant != "default" {
		t.Fatalf("POST /submit matched post variant %q, want default", variant)
	}
}

func TestFindVariantPrefersLongestPrefix(t *testing.T) {
	transport := newTestTransport(`
http-get {
	set uri "/ /search";
	client {
		metadata {
			base64;
			parameter "id";
		}
	}
	server {
		output {
			print;
		}
	}
}
http-get "specific" {
	set uri "/search/results";
	client {
		metadata {
			base64;
			parameter "id";
		}
	}
	server {
		output {
			print;
		}
	}
}
`)

	if variant := transport.findGetVariant("GET", "/search/results/1"); variant != "specific" {
		t.Fatalf("GET /search/results/1 matched variant %q, want specific", variant)
	}
}

func TestEffectiveHostHeadersIncludesProfileHost(t *testing.T) {
	transport := transportWithProfileHost("google.com")
	transport.Config.HostHeader = []string{"192.0.2.10"}

	hosts := transport.effectiveHostHeaders()

	assertStringPresent(t, hosts, "192.0.2.10")
	assertStringPresent(t, hosts, "google.com")
}

func TestGeneratedCertificateIncludesProfileHost(t *testing.T) {
	transport := transportWithProfileHost("google.com")
	transport.Config.HostBind = "192.0.2.10"

	dir := t.TempDir()
	certPath := filepath.Join(dir, "listener.crt")
	keyPath := filepath.Join(dir, "listener.key")

	if err := transport.generateSelfSignedCert(certPath, keyPath); err != nil {
		t.Fatalf("generateSelfSignedCert returned error: %v", err)
	}

	cert := readTestCertificate(t, certPath)
	if err := cert.VerifyHostname("google.com"); err != nil {
		t.Fatalf("generated certificate does not cover profile Host header: %v", err)
	}
	if err := cert.VerifyHostname("192.0.2.10"); err != nil {
		t.Fatalf("generated certificate does not cover bind IP: %v", err)
	}
}

func TestCertificateCoversConfiguredHostsRejectsStaleCert(t *testing.T) {
	oldTransport := &TransportMalleable{Config: TransportConfig{HostBind: "192.0.2.10"}}
	dir := t.TempDir()
	oldCertPath := filepath.Join(dir, "old.crt")
	oldKeyPath := filepath.Join(dir, "old.key")

	if err := oldTransport.generateSelfSignedCert(oldCertPath, oldKeyPath); err != nil {
		t.Fatalf("generateSelfSignedCert returned error: %v", err)
	}
	oldCertPEM, err := os.ReadFile(oldCertPath)
	if err != nil {
		t.Fatalf("failed to read generated cert: %v", err)
	}

	newTransport := transportWithProfileHost("google.com")
	newTransport.Config.HostBind = "192.0.2.10"
	if newTransport.certificateCoversConfiguredHosts(oldCertPEM) {
		t.Fatal("certificateCoversConfiguredHosts accepted an IP-only cert for a profile Host header")
	}
}

func transportWithProfileHost(host string) *TransportMalleable {
	profile := openmalleable.NewMalleableProfile(`
set useragent "Mozilla/5.0";
http-get {
    set uri "/mobile-home.css";
    client {
        header "Host" "` + host + `";
        metadata {
            base64;
            parameter "id";
        }
    }
    server {
        output {
            print;
        }
    }
}
`)
	return &TransportMalleable{Profile: profile}
}

func readTestCertificate(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func assertStringPresent(t *testing.T, values []string, expected string) {
	t.Helper()

	for _, value := range values {
		if value == expected {
			return
		}
	}
	t.Fatalf("%q not present in %v", expected, values)
}
