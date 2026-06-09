package metrics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certauth is a minted certificate plus its key, used to sign children.
type certauth struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func mint(t *testing.T, cn string, isCA bool, eku []x509.ExtKeyUsage, ips []net.IP, parent *certauth) certauth {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IPAddresses:           ips,
	}

	signerCert := tmpl
	signerKey := key
	if parent != nil {
		signerCert = parent.cert
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certauth{cert: cert, key: key, der: der}
}

func writePEM(t *testing.T, dir, name string, blocks ...*pem.Block) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	for _, b := range blocks {
		require.NoError(t, pem.Encode(f, b))
	}
	return path
}

func certBlock(der []byte) *pem.Block { return &pem.Block{Type: "CERTIFICATE", Bytes: der} }

func keyBlock(t *testing.T, key *ecdsa.PrivateKey) *pem.Block {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return &pem.Block{Type: "PRIVATE KEY", Bytes: der}
}

// tlsClientCert builds a client tls.Certificate, presenting the leaf followed by
// any intermediate DERs (mirroring how a real client sends its chain).
func tlsClientCert(leaf certauth, intermediates ...[]byte) tls.Certificate {
	chain := [][]byte{leaf.der}
	chain = append(chain, intermediates...)
	return tls.Certificate{Certificate: chain, PrivateKey: leaf.key}
}

func TestBuildTLSConfigClientCertVerification(t *testing.T) {
	dir := t.TempDir()

	// Trusted root CA, plus a server cert and a client cert under it.
	root := mint(t, "root", true, nil, nil, nil)
	server := mint(t, "server", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.IPv4(127, 0, 0, 1)}, &root)
	client := mint(t, "client", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, &root)

	// Two-tier chain: root -> intermediate -> leaf. This is the case the old
	// hand-rolled verifier rejected because it supplied no Intermediates pool.
	intermediate := mint(t, "intermediate", true, nil, nil, &root)
	clientViaIntermediate := mint(t, "client-2tier", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, &intermediate)

	// A completely separate CA the server must NOT trust.
	otherRoot := mint(t, "other-root", true, nil, nil, nil)
	untrustedClient := mint(t, "untrusted", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, &otherRoot)

	caFile := writePEM(t, dir, "ca.crt", certBlock(root.der))
	certFile := writePEM(t, dir, "tls.crt", certBlock(server.der))
	keyFile := writePEM(t, dir, "tls.key", keyBlock(t, server.key))

	serverCfg, err := buildTLSConfig(context.Background(), &TLSConfig{
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: caFile,
	})
	require.NoError(t, err)
	require.Equal(t, tls.RequireAndVerifyClientCert, serverCfg.ClientAuth)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = serverCfg
	ts.StartTLS()
	defer ts.Close()

	// The client trusts the server's root, so the only verification that can fail
	// is the server checking the client's certificate.
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(root.cert)

	get := func(clientCerts []tls.Certificate) (int, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      clientRoots,
			Certificates: clientCerts,
		}}}
		defer c.CloseIdleConnections()
		resp, err := c.Get(ts.URL)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	t.Run("trusted single-tier client is accepted", func(t *testing.T) {
		code, err := get([]tls.Certificate{tlsClientCert(client)})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("trusted two-tier client chain is accepted", func(t *testing.T) {
		code, err := get([]tls.Certificate{tlsClientCert(clientViaIntermediate, intermediate.der)})
		require.NoError(t, err, "leaf signed by an intermediate that chains to the CA must verify")
		assert.Equal(t, http.StatusOK, code)
	})

	t.Run("client from an untrusted CA is rejected", func(t *testing.T) {
		_, err := get([]tls.Certificate{tlsClientCert(untrustedClient)})
		assert.Error(t, err, "a client cert signed by an untrusted CA must be rejected")
	})

	t.Run("missing client cert is rejected", func(t *testing.T) {
		_, err := get(nil)
		assert.Error(t, err, "RequireAndVerifyClientCert must reject a connection with no client cert")
	})
}
