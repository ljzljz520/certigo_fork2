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

package cli

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"

	"github.com/square/certigo/cli/terminal"
)

// Minimal local PKI for end-to-end OCSP tests. Everything is generated in
// memory and served by a loopback HTTP server, so no network or frozen clock
// is required.
type cliOCSPPKI struct {
	rootA    *x509.Certificate
	rootAKey crypto.Signer
	rootB    *x509.Certificate
	rootBKey crypto.Signer
	intA     *x509.Certificate
	intB     *x509.Certificate
	intKey   crypto.Signer
	leaf     *x509.Certificate
	other    *x509.Certificate
	noOCSP   *x509.Certificate
}

var cliOCSPSerial int64

func cliOCSPNextSerial() *big.Int {
	cliOCSPSerial++
	return big.NewInt(cliOCSPSerial)
}

func cliOCSPKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func cliOCSPIssue(t *testing.T, template, parent *x509.Certificate, signer, key crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if key == nil {
		key = cliOCSPKey(t)
	}
	if parent == nil {
		parent = template
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func cliOCSPBuildPKI(t *testing.T, ocspURL string) *cliOCSPPKI {
	t.Helper()
	now := time.Now()
	pki := &cliOCSPPKI{}

	caTemplate := func(cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          cliOCSPNextSerial(),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * 365 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
	}
	pki.rootA, pki.rootAKey = cliOCSPIssue(t, caTemplate("Test Root A"), nil, nil, nil)
	pki.rootB, pki.rootBKey = cliOCSPIssue(t, caTemplate("Test Root B"), nil, nil, nil)

	pki.intKey = cliOCSPKey(t)
	pki.intA, _ = cliOCSPIssue(t, caTemplate("Test Intermediate"), pki.rootA, pki.rootAKey, pki.intKey)
	pki.intB, _ = cliOCSPIssue(t, caTemplate("Test Intermediate"), pki.rootB, pki.rootBKey, pki.intKey)

	leafTemplate := func(cn, url string) *x509.Certificate {
		cert := &x509.Certificate{
			SerialNumber:          cliOCSPNextSerial(),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(24 * 30 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{cn},
		}
		if url != "" {
			cert.OCSPServer = []string{url}
		}
		return cert
	}
	pki.leaf, _ = cliOCSPIssue(t, leafTemplate("example.com", ocspURL), pki.intA, pki.intKey, nil)
	pki.other, _ = cliOCSPIssue(t, leafTemplate("other.example.com", ocspURL), pki.intA, pki.intKey, nil)
	// Same verifiable name as leaf, but without an OCSP responder URL.
	pki.noOCSP, _ = cliOCSPIssue(t, leafTemplate("example.com", ""), pki.intA, pki.intKey, nil)
	return pki
}

func cliOCSPResponse(t *testing.T, pki *cliOCSPPKI, serial *big.Int, status int,
	thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	template := ocsp.Response{
		SerialNumber: serial,
		Status:       status,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		template.RevokedAt = thisUpdate
		template.RevocationReason = ocsp.KeyCompromise
	}
	raw, err := ocsp.CreateResponse(pki.intA, pki.intA, template, pki.intKey)
	require.NoError(t, err)
	return raw
}

func cliOCSPWritePEMFile(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	file, err := os.CreateTemp("", "ocsp-cli-*.pem")
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	for _, cert := range certs {
		require.NoError(t, pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	t.Cleanup(func() { _ = os.Remove(file.Name()) })
	return file.Name()
}

func runCertigoVerify(t *testing.T, chainPath, caPath string, strict, asJSON bool) (int, string, string) {
	t.Helper()
	// Explicit on/off values are used because the global kingpin app is
	// parsed repeatedly inside one test process and otherwise retains
	// boolean values from the previous Run.
	args := []string{"verify", "--name", "example.com", "--ca", caPath,
		"--no-strict-ocsp", "--no-json"}
	if strict {
		args[len(args)-2] = "--strict-ocsp"
	}
	if asJSON {
		args[len(args)-1] = "--json"
	}
	args = append(args, chainPath)

	term := &terminal.TestTerminal{Width: 80}

	// JSON output is written straight to os.Stdout by the verify command, so
	// capture it when requested.
	var code int
	if asJSON {
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdout = w
		code = Run(args, term)
		_ = w.Close()
		os.Stdout = oldStdout
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		return code, string(data), term.ErrorBuf.String()
	}
	code = Run(args, term)
	return code, term.OutputBuf.String(), term.ErrorBuf.String()
}

var rfc822Timestamp = regexp.MustCompile(`\d{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2} UTC`)

// TestVerifyCommandOCSP covers the user-visible contract: locally produced
// responses (good, trusted-revoked, expired/freshness failures, responses
// bound to the wrong certificate) keep default-mode reporting compatible
// (exit 0, findings printed), while --strict-ocsp turns every non-good
// conclusion into verification failure (exit 1).
func TestVerifyCommandOCSP(t *testing.T) {
	now := time.Now()

	type expectation struct {
		name            string
		buildResponse   func(pki *cliOCSPPKI) []byte
		leaf            func(pki *cliOCSPPKI) *x509.Certificate
		defaultContains string
		defaultAbsent   string
		strictExitCode  int
		strictContains  string
	}
	cases := []expectation{
		{
			name: "fresh good",
			buildResponse: func(pki *cliOCSPPKI) []byte {
				return cliOCSPResponse(t, pki, pki.leaf.SerialNumber, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
			},
			leaf:            func(pki *cliOCSPPKI) *x509.Certificate { return pki.leaf },
			defaultContains: "Good",
			strictExitCode:  0,
			strictContains:  "Good",
		},
		{
			name: "trusted revoked is reported but only fails under strict",
			buildResponse: func(pki *cliOCSPPKI) []byte {
				return cliOCSPResponse(t, pki, pki.leaf.SerialNumber, ocsp.Revoked, now.Add(-2*time.Hour), now.Add(time.Hour))
			},
			leaf:            func(pki *cliOCSPPKI) *x509.Certificate { return pki.leaf },
			defaultContains: "Revoked",
			strictExitCode:  1,
			strictContains:  "strict OCSP policy: certificate was revoked",
		},
		{
			name: "expired response is not good and fails under strict",
			buildResponse: func(pki *cliOCSPPKI) []byte {
				return cliOCSPResponse(t, pki, pki.leaf.SerialNumber, ocsp.Good, now.Add(-48*time.Hour), now.Add(-time.Hour))
			},
			leaf:            func(pki *cliOCSPPKI) *x509.Certificate { return pki.leaf },
			defaultContains: "unable to check status",
			defaultAbsent:   "\n\tGood",
			strictExitCode:  1,
			strictContains:  "unable to obtain a current OCSP status",
		},
		{
			name: "response for the wrong certificate fails under strict",
			buildResponse: func(pki *cliOCSPPKI) []byte {
				return cliOCSPResponse(t, pki, pki.other.SerialNumber, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))
			},
			leaf:            func(pki *cliOCSPPKI) *x509.Certificate { return pki.leaf },
			defaultContains: "unable to check status",
			strictExitCode:  1,
			strictContains:  "unable to obtain a current OCSP status",
		},
		{
			name:           "missing OCSP is silent by default and fails under strict",
			buildResponse:  func(pki *cliOCSPPKI) []byte { return nil },
			leaf:           func(pki *cliOCSPPKI) *x509.Certificate { return pki.noOCSP },
			defaultAbsent:  "OCSP",
			strictExitCode: 1,
			strictContains: "no OCSP revocation status is available",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var response []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write(response)
			}))
			defer server.Close()

			pki := cliOCSPBuildPKI(t, server.URL)
			response = tc.buildResponse(pki)

			chainPath := cliOCSPWritePEMFile(t, tc.leaf(pki), pki.intA)
			caPath := cliOCSPWritePEMFile(t, pki.rootA)

			// Default mode: findings are reported, exit code stays 0.
			code, out, errOut := runCertigoVerify(t, chainPath, caPath, false, false)
			assert.Equal(t, 0, code, "default mode must not change the exit code: %s", errOut)
			assert.Empty(t, errOut)
			assert.Contains(t, out, tc.defaultContains)
			if tc.defaultAbsent != "" {
				assert.NotContains(t, out, tc.defaultAbsent)
			}

			// Strict mode: exit code reflects the strict policy.
			strictCode, strictOut, strictErr := runCertigoVerify(t, chainPath, caPath, true, false)
			assert.Equal(t, tc.strictExitCode, strictCode, strictErr)
			assert.Empty(t, strictErr)
			assert.Contains(t, strictOut, tc.strictContains)
		})
	}
}

// TestVerifyCommandOCSPMultipath verifies that with two valid chains (leaf via
// a cross-signed intermediate to two distinct roots) the conclusion is kept
// per validation path and the report, JSON and exit code stay stable and do
// not depend on path ordering.
func TestVerifyCommandOCSPMultipath(t *testing.T) {
	now := time.Now()

	var response []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(response)
	}))
	defer server.Close()

	pki := cliOCSPBuildPKI(t, server.URL)
	// The response is signed by the shared intermediate key, so it validates
	// on every path regardless of the order x509.Verify returns them.
	response = cliOCSPResponse(t, pki, pki.leaf.SerialNumber, ocsp.Good, now.Add(-time.Hour), now.Add(time.Hour))

	chainPath := cliOCSPWritePEMFile(t, pki.leaf, pki.intA, pki.intB)
	caPath := cliOCSPWritePEMFile(t, pki.rootA, pki.rootB)

	for _, strict := range []bool{false, true} {
		code, out, errOut := runCertigoVerify(t, chainPath, caPath, strict, false)
		assert.Equal(t, 0, code, "strict=%v: %s", strict, errOut)
		assert.Contains(t, out, "Found 2 valid certificate chain(s)")
		assert.Equal(t, 1, strings.Count(out, "Checked OCSP status for certificate"),
			"exactly one aggregate OCSP section must be printed")
		assert.Contains(t, out, "\n\tGood")

		// Re-running must produce the same report regardless of path order.
		code2, out2, _ := runCertigoVerify(t, chainPath, caPath, strict, false)
		assert.Equal(t, code, code2)
		assert.Equal(t, rfc822Timestamp.ReplaceAllString(out, "TS"),
			rfc822Timestamp.ReplaceAllString(out2, "TS"))
	}

	// The machine-readable report retains one result per validation path.
	code, jsonOut, errOut := runCertigoVerify(t, chainPath, caPath, true, true)
	assert.Equal(t, 0, code, errOut)
	assert.Contains(t, jsonOut, `"ocsp_results"`)
	assert.Equal(t, 2, strings.Count(jsonOut, `"issuer":"CN=Test Intermediate"`))
	assert.Contains(t, jsonOut, `"ocsp_response"`)
	assert.NotContains(t, jsonOut, `"ocsp_error":`)
}
