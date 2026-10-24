// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// Local, fully in-memory test PKI. All certificates are generated with keys
// and validity windows relative to the current time, so these tests need no
// frozen clock and no network access (a loopback httptest server is used where
// fetching is exercised).
type ocspTestPKI struct {
	now      time.Time
	rootA    *x509.Certificate
	rootAKey crypto.Signer
	rootB    *x509.Certificate
	rootBKey crypto.Signer

	// intA and intB are two cross-certificates of the same intermediate key.
	intA   *x509.Certificate
	intB   *x509.Certificate
	intKey crypto.Signer

	leaf     *x509.Certificate
	leafKey  crypto.Signer
	other    *x509.Certificate // second leaf issued by intA, distinct serial
	otherKey crypto.Signer
}

var ocspTestSerial int64

func ocspNextSerial() *big.Int {
	ocspTestSerial++
	return big.NewInt(ocspTestSerial)
}

func ocspGenerateKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func ocspIssueCert(t *testing.T, template, parent *x509.Certificate, signer, key crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if key == nil {
		key = ocspGenerateKey(t)
	}
	if parent == nil {
		// Self-signed root.
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func ocspCATemplate(t *testing.T, cn string, now time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          ocspNextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func ocspLeafTemplate(t *testing.T, cn, ocspURL string, now time.Time) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          ocspNextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * 30 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{cn},
	}
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	return tmpl
}

func newOCSPTestPKI(t *testing.T, ocspURL string) *ocspTestPKI {
	t.Helper()
	pki := &ocspTestPKI{now: time.Now()}

	pki.rootA, pki.rootAKey = ocspIssueCert(t, ocspCATemplate(t, "Test Root A", pki.now), nil, nil, nil)
	pki.rootB, pki.rootBKey = ocspIssueCert(t, ocspCATemplate(t, "Test Root B", pki.now), nil, nil, nil)

	pki.intKey = ocspGenerateKey(t)
	pki.intA, _ = ocspIssueCert(t, ocspCATemplate(t, "Test Intermediate", pki.now), pki.rootA, pki.rootAKey, pki.intKey)
	pki.intB, _ = ocspIssueCert(t, ocspCATemplate(t, "Test Intermediate", pki.now), pki.rootB, pki.rootBKey, pki.intKey)

	pki.leaf, pki.leafKey = ocspIssueCert(t, ocspLeafTemplate(t, "example.com", ocspURL, pki.now), pki.intA, pki.intKey, nil)
	pki.other, pki.otherKey = ocspIssueCert(t, ocspLeafTemplate(t, "other.example.com", ocspURL, pki.now), pki.intA, pki.intKey, nil)
	return pki
}

// ocspResponderTemplate builds a delegated OCSP responder certificate issued
// by the given issuer.
func ocspResponderTemplate(t *testing.T, cn string, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          ocspNextSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
}

// ocspSignResponse builds a DER OCSP response. issuer controls the CertID
// (issuer name/key hashes and serial); signer controls the actual signature;
// responder is the embedded delegated responder certificate, or nil for a
// response signed directly by the issuer.
func ocspSignResponse(t *testing.T, issuer, responder *x509.Certificate, signer crypto.Signer, serial *big.Int,
	status int, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	// CreateResponse derives the ResponderID from responderCert; for a
	// directly signing CA it is the issuer itself.
	responderID := issuer
	if responder != nil {
		responderID = responder
	}
	template := ocsp.Response{
		SerialNumber: serial,
		Status:       status,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
		// A delegated responder certificate must be embedded in the response.
		Certificate: responder,
	}
	if status == ocsp.Revoked {
		template.RevokedAt = thisUpdate
		template.RevocationReason = ocsp.KeyCompromise
	}
	raw, err := ocsp.CreateResponse(issuer, responderID, template, signer)
	require.NoError(t, err)
	return raw
}

func ocspWriteCAFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	file, err := os.CreateTemp("", "ocsp-ca-*.pem")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	for _, cert := range certs {
		require.NoError(t, pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	return file.Name()
}

func TestCheckOCSPResponseVerification(t *testing.T) {
	pki := newOCSPTestPKI(t, "http://ocsp.invalid/")
	now := pki.now
	chain := []*x509.Certificate{pki.leaf, pki.intA}

	// A fresh, directly CA-signed good response binds to the leaf.
	good := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
	t.Run("good response binds to leaf", func(t *testing.T) {
		result := checkOCSP(chain, good)
		require.NoError(t, result.err)
		require.NotNil(t, result.response)
		assert.Equal(t, ocsp.Good, result.response.Status)
		assert.True(t, result.stapled)
		assert.Equal(t, "CN=Test Intermediate", result.issuerCN)
	})

	t.Run("revoked response is parsed", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Revoked, now.Add(-2*time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.NoError(t, result.err)
		require.NotNil(t, result.response)
		assert.Equal(t, ocsp.Revoked, result.response.Status)
		assert.Equal(t, ocsp.KeyCompromise, result.response.RevocationReason)
	})

	// A response about a different certificate ("wrong certificate") must not
	// be attributed to the target leaf, even though it is signed by the right
	// CA.
	t.Run("response for wrong certificate rejected", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.other.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Nil(t, result.response)
		assert.Contains(t, result.err.Error(), "matching")
	})

	t.Run("expired response rejected", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-48*time.Hour), now.Add(-time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Nil(t, result.response)
		assert.Contains(t, result.err.Error(), "expired")
	})

	t.Run("not yet valid response rejected", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(time.Hour), now.Add(48*time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "not yet valid")
	})

	t.Run("response without nextUpdate rejected", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), time.Time{})
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "nextUpdate")
	})

	// A response signed by the correct key but whose CertID names a different
	// issuer must not bind to this leaf/issuer pair.
	t.Run("CertID mismatch rejected", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.rootB, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "CertID does not match")
	})

	t.Run("unknown status preserved", func(t *testing.T) {
		raw := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
			ocsp.Unknown, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.NoError(t, result.err)
		require.NotNil(t, result.response)
		assert.Equal(t, ocsp.Unknown, result.response.Status)
	})

	t.Run("no OCSP server means skipped", func(t *testing.T) {
		noOCSPLeaf, _ := ocspIssueCert(t, ocspLeafTemplate(t, "no-ocsp.example.com", "", now), pki.intA, pki.intKey, nil)
		result := checkOCSP([]*x509.Certificate{noOCSPLeaf, pki.intA}, good)
		assert.True(t, result.skipped)
		require.ErrorIs(t, result.err, errSkippedRevocationCheck)
	})
}

func TestCheckOCSPResponderAuthorization(t *testing.T) {
	pki := newOCSPTestPKI(t, "http://ocsp.invalid/")
	now := pki.now
	chain := []*x509.Certificate{pki.leaf, pki.intA}

	t.Run("delegated responder without OCSPSigning EKU rejected", func(t *testing.T) {
		key := ocspGenerateKey(t)
		tmpl := ocspResponderTemplate(t, "Unauthorized OCSP Responder",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-time.Hour), now.Add(24*time.Hour))
		responder, _ := ocspIssueCert(t, tmpl, pki.intA, pki.intKey, key)
		raw := ocspSignResponse(t, pki.intA, responder, key, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "not authorized")
	})

	t.Run("authorized delegated responder accepted", func(t *testing.T) {
		key := ocspGenerateKey(t)
		tmpl := ocspResponderTemplate(t, "OCSP Responder",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(-time.Hour), now.Add(24*time.Hour))
		responder, _ := ocspIssueCert(t, tmpl, pki.intA, pki.intKey, key)
		raw := ocspSignResponse(t, pki.intA, responder, key, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.NoError(t, result.err)
		assert.Equal(t, ocsp.Good, result.response.Status)
	})

	t.Run("delegated responder signed by unrelated CA rejected", func(t *testing.T) {
		key := ocspGenerateKey(t)
		tmpl := ocspResponderTemplate(t, "Other CA OCSP Responder",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(-time.Hour), now.Add(24*time.Hour))
		responder, _ := ocspIssueCert(t, tmpl, pki.rootA, pki.rootAKey, key)
		raw := ocspSignResponse(t, pki.intA, responder, key, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "parsing OCSP response")
	})

	t.Run("expired delegated responder certificate rejected", func(t *testing.T) {
		key := ocspGenerateKey(t)
		tmpl := ocspResponderTemplate(t, "Expired OCSP Responder",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(-48*time.Hour), now.Add(-time.Hour))
		responder, _ := ocspIssueCert(t, tmpl, pki.intA, pki.intKey, key)
		raw := ocspSignResponse(t, pki.intA, responder, key, pki.leaf.SerialNumber,
			ocsp.Good, now.Add(-30*time.Minute), now.Add(30*time.Minute))
		result := checkOCSP(chain, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "responder certificate")
	})

	t.Run("issuer forbidding delegation rejects responder", func(t *testing.T) {
		// A cross-certificate of the intermediate whose EKU extension lists
		// usages other than OCSP signing forbids delegation (RFC 6960).
		forbidTmpl := ocspCATemplate(t, "Test Intermediate", now)
		forbidTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		intForbid, _ := ocspIssueCert(t, forbidTmpl, pki.rootA, pki.rootAKey, pki.intKey)
		leafForbid, _ := ocspIssueCert(t, ocspLeafTemplate(t, "forbid.example.com", "http://ocsp.invalid/", now),
			intForbid, pki.intKey, nil)

		key := ocspGenerateKey(t)
		respTmpl := ocspResponderTemplate(t, "OCSP Responder",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, now.Add(-time.Hour), now.Add(24*time.Hour))
		responder, _ := ocspIssueCert(t, respTmpl, intForbid, pki.intKey, key)
		raw := ocspSignResponse(t, intForbid, responder, key, leafForbid.SerialNumber,
			ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
		result := checkOCSP([]*x509.Certificate{leafForbid, intForbid}, raw)
		require.Error(t, result.err)
		assert.Contains(t, result.err.Error(), "does not delegate OCSP signing")
	})
}

func TestCheckOCSPFetchedFromLocalServer(t *testing.T) {
	now := time.Now()

	// Start the server first, because the leaf embeds its URL.
	var goodResponse []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.NotEmpty(t, body)
			assert.Equal(t, "application/ocsp-request", r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(goodResponse)
	}))
	defer server.Close()

	pki := newOCSPTestPKI(t, server.URL)
	goodResponse = ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))

	result := checkOCSP([]*x509.Certificate{pki.leaf, pki.intA}, nil)
	require.NoError(t, result.err)
	require.NotNil(t, result.response)
	assert.Equal(t, ocsp.Good, result.response.Status)
	assert.False(t, result.stapled)

	// A pre-signed OCSP error response (unauthorized) is surfaced as an error.
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(ocsp.UnauthorizedErrorResponse)
	}))
	defer errorServer.Close()
	pki2 := newOCSPTestPKI(t, errorServer.URL)
	errResult := checkOCSP([]*x509.Certificate{pki2.leaf, pki2.intA}, nil)
	require.Error(t, errResult.err)
	assert.Nil(t, errResult.response)
}

func TestAggregateOCSPResultsOrderIndependence(t *testing.T) {
	pki := newOCSPTestPKI(t, "http://ocsp.invalid/")
	now := pki.now
	chain := []*x509.Certificate{pki.leaf, pki.intA}

	good := checkOCSP(chain, ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour)))
	revoked := checkOCSP(chain, ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Revoked, now.Add(-2*time.Hour), now.Add(time.Hour)))
	unknown := checkOCSP(chain, ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Unknown, now.Add(-time.Hour), now.Add(time.Hour)))
	expired := checkOCSP(chain, ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-48*time.Hour), now.Add(-time.Hour)))
	wrongCert := checkOCSP(chain, ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.other.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour)))
	skipped := chainOCSPResult{skipped: true, err: errSkippedRevocationCheck}

	sameAggregate := func(a, b chainOCSPResult) bool {
		aStatus, bStatus := -1, -1
		if a.response != nil {
			aStatus = a.response.Status
		}
		if b.response != nil {
			bStatus = b.response.Status
		}
		aErr, bErr := "", ""
		if a.err != nil {
			aErr = a.err.Error()
		}
		if b.err != nil {
			bErr = b.err.Error()
		}
		return aStatus == bStatus && aErr == bErr && a.skipped == b.skipped
	}

	cases := []struct {
		name   string
		first  chainOCSPResult
		second chainOCSPResult
	}{
		{"good and error", good, expired},
		{"revoked and good", revoked, good},
		{"unknown and good", unknown, good},
		{"revoked and error", revoked, expired},
		{"two distinct errors", expired, wrongCert},
		{"good and skipped", good, skipped},
		{"error and skipped", expired, skipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forward := aggregateOCSPResults([]chainOCSPResult{tc.first, tc.second})
			backward := aggregateOCSPResults([]chainOCSPResult{tc.second, tc.first})
			assert.True(t, sameAggregate(forward, backward),
				"aggregate changed with path order: %+v vs %+v", forward, backward)
		})
	}

	// Severity ranking: revoked beats good and unknown; unknown beats good.
	assert.Equal(t, ocsp.Revoked, aggregateOCSPResults([]chainOCSPResult{good, revoked}).response.Status)
	assert.Equal(t, ocsp.Unknown, aggregateOCSPResults([]chainOCSPResult{good, unknown}).response.Status)
	assert.Equal(t, ocsp.Good, aggregateOCSPResults([]chainOCSPResult{good, expired}).response.Status)

	// A successful path suppresses per-path errors; all-error paths yield the
	// deterministic (lexicographically first) error.
	agg := aggregateOCSPResults([]chainOCSPResult{expired, wrongCert})
	require.Error(t, agg.err)
	assert.Equal(t, agg.err.Error(), aggregateOCSPResults([]chainOCSPResult{wrongCert, expired}).err.Error())

	assert.True(t, aggregateOCSPResults([]chainOCSPResult{skipped, skipped}).skipped)
}

// TestVerifyChainOCSPMultiPath exercises real x509 path building with a
// cross-signed intermediate and a stapled OCSP response: the conclusion must
// be retained per path and stay stable under path reordering.
func TestVerifyChainOCSPMultiPath(t *testing.T) {
	pki := newOCSPTestPKI(t, "http://ocsp.invalid/")
	caPath := ocspWriteCAFile(t, pki.rootA, pki.rootB)
	certs := []*x509.Certificate{pki.leaf, pki.intA, pki.intB}

	staple := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, pki.now.Add(-time.Hour), pki.now.Add(time.Hour))

	result := VerifyChain(certs, staple, "", caPath, false)
	require.Empty(t, result.Error)
	require.Len(t, result.Chains, 2, "cross-signed intermediate should yield two validation paths")
	require.Len(t, result.OCSPResults, 2, "an OCSP result must be retained per path")
	for i, r := range result.OCSPResults {
		require.NotNilf(t, r.Status, "path %d should have a verified response", i)
		assert.Equalf(t, ocsp.Good, r.Status.Status, "path %d", i)
		assert.Truef(t, r.WasStapled, "path %d", i)
		assert.Falsef(t, r.Skipped, "path %d", i)
	}
	require.NotNil(t, result.OCSPStatus)
	assert.Equal(t, ocsp.Good, result.OCSPStatus.Status)
	assert.Empty(t, result.OCSPError)

	// The aggregate must not depend on the order x509.Verify returns paths.
	intermediates := x509.NewCertPool()
	intermediates.AddCert(pki.intA)
	intermediates.AddCert(pki.intB)
	roots := x509.NewCertPool()
	roots.AddCert(pki.rootA)
	roots.AddCert(pki.rootB)
	chains, err := pki.leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates})
	require.NoError(t, err)
	require.Len(t, chains, 2)

	perPathForward, aggForward := checkOCSPForChains(chains, staple)
	reversed := make([][]*x509.Certificate, len(chains))
	for i, chain := range chains {
		reversed[len(chains)-1-i] = chain
	}
	perPathReversed, aggReversed := checkOCSPForChains(reversed, staple)

	assert.Equal(t, aggForward.response.Status, aggReversed.response.Status)
	assert.Equal(t, countGoodPaths(perPathForward), countGoodPaths(perPathReversed))
}

func countGoodPaths(results []chainOCSPResult) int {
	n := 0
	for _, r := range results {
		if r.response != nil && r.response.Status == ocsp.Good {
			n++
		}
	}
	return n
}

func TestVerifyChainStrictOCSPPolicy(t *testing.T) {
	pki := newOCSPTestPKI(t, "http://ocsp.invalid/")
	caPath := ocspWriteCAFile(t, pki.rootA)
	certs := []*x509.Certificate{pki.leaf, pki.intA}
	now := pki.now

	good := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
	revoked := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Revoked, now.Add(-2*time.Hour), now.Add(time.Hour))
	unknown := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Unknown, now.Add(-time.Hour), now.Add(time.Hour))
	expired := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.leaf.SerialNumber,
		ocsp.Good, now.Add(-48*time.Hour), now.Add(-time.Hour))
	wrongCert := ocspSignResponse(t, pki.intA, nil, pki.intKey, pki.other.SerialNumber,
		ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))

	cases := []struct {
		name        string
		staple      []byte
		strictFail  bool
		expectError string
	}{
		{"fresh good passes strict", good, false, ""},
		{"trusted revoked fails strict", revoked, true, "revoked"},
		{"unknown fails strict", unknown, true, "unknown"},
		{"expired fails strict", expired, true, "current OCSP status"},
		{"wrong-cert response fails strict", wrongCert, true, "current OCSP status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Default behavior stays compatible: OCSP findings never fail the
			// overall chain verification.
			compat := VerifyChain(certs, tc.staple, "", caPath, false)
			assert.Empty(t, compat.Error, "default mode must not fail verification")

			strict := VerifyChain(certs, tc.staple, "", caPath, true)
			if tc.strictFail {
				require.NotEmpty(t, strict.Error)
				assert.Contains(t, strict.Error, "strict OCSP policy")
				assert.Contains(t, strict.Error, tc.expectError)
			} else {
				assert.Empty(t, strict.Error)
			}
		})
	}

	// A revoked status is still *reported* in default mode (red status, but
	// verification error and exit-equivalent stay empty).
	reported := VerifyChain(certs, revoked, "", caPath, false)
	require.NotNil(t, reported.OCSPStatus)
	assert.Equal(t, ocsp.Revoked, reported.OCSPStatus.Status)
	assert.Empty(t, reported.Error)

	// Expired responses surface as OCSP errors, never as Good.
	stale := VerifyChain(certs, expired, "", caPath, false)
	assert.Nil(t, stale.OCSPStatus)
	assert.Contains(t, stale.OCSPError, "expired")

	// Missing OCSP entirely: silent by default, failure under strict.
	noOCSPLeaf, _ := ocspIssueCert(t, ocspLeafTemplate(t, "no-ocsp.example.com", "", now), pki.intA, pki.intKey, nil)
	missingCerts := []*x509.Certificate{noOCSPLeaf, pki.intA}
	compat := VerifyChain(missingCerts, nil, "", caPath, false)
	assert.Empty(t, compat.Error)
	assert.Empty(t, compat.OCSPError)
	assert.Nil(t, compat.OCSPStatus)
	strict := VerifyChain(missingCerts, nil, "", caPath, true)
	require.NotEmpty(t, strict.Error)
	assert.Contains(t, strict.Error, "no OCSP revocation status")
}
