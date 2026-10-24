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
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ocsp"
)

var (
	errSkippedRevocationCheck = errors.New("skipped revocation check")

	revocationStatusColor = map[int]*color.Color{
		ocsp.Good:    green,
		ocsp.Revoked: red,
		ocsp.Unknown: yellow,
	}

	revocationStatusDescription = map[int]string{
		ocsp.Good:    "Good",
		ocsp.Revoked: "Revoked",
		ocsp.Unknown: "Unknown",
	}

	revocationReasonDescription = map[int]string{
		ocsp.Unspecified:          "Unspecified",
		ocsp.KeyCompromise:        "KeyCompromise",
		ocsp.CACompromise:         "CACompromise",
		ocsp.AffiliationChanged:   "AffiliationChanged",
		ocsp.Superseded:           "Superseded",
		ocsp.CessationOfOperation: "CessationOfOperation",
		ocsp.CertificateHold:      "CertificateHold",
		ocsp.RemoveFromCRL:        "RemoveFromCRL",
		ocsp.PrivilegeWithdrawn:   "PrivilegeWithdrawn",
		ocsp.AACompromise:         "AACompromise",
	}

	ocspHttpClient = &http.Client{
		// Set a timeout so we don't block forever on broken servers.
		Timeout: 5 * time.Second,
	}
)

const (
	// We retry multiple times, because OCSP servers are often a bit unreliable.
	maxOCSPValidationRetries = 3

	// RFC 6960 allows for a small clock skew between the responder and the
	// client when checking thisUpdate/nextUpdate.
	ocspTimingSkew = 90 * time.Second
)

// chainOCSPResult is the outcome of an OCSP check for a single validation
// path (chain). Exactly one of response/err is meaningful, unless skipped is
// true, in which case no OCSP check was attempted for this path.
type chainOCSPResult struct {
	// response is the parsed, cryptographically verified OCSP response whose
	// CertID binds to the path's leaf certificate.
	response *ocsp.Response
	// err describes why no trustworthy, current status could be obtained.
	err error
	// skipped is true when the path's leaf advertises no OCSP responder.
	skipped bool
	// stapled is true when the response bytes came from a TLS staple.
	stapled bool
	// issuerCN identifies the issuer used for this path, which helps tell
	// multiple validation paths apart in per-path results.
	issuerCN string
}

func checkOCSP(chain []*x509.Certificate, ocspStaple []byte) chainOCSPResult {
	result := chainOCSPResult{stapled: len(ocspStaple) > 0}
	if len(chain) < 2 {
		// Nothing to check here
		result.skipped = true
		result.err = errSkippedRevocationCheck
		return result
	}

	leaf, issuer := chain[0], chain[1]
	result.issuerCN = PrintCommonName(issuer.Subject)
	if len(leaf.OCSPServer) == 0 {
		result.skipped = true
		result.err = errSkippedRevocationCheck
		return result
	}

	retries := maxOCSPValidationRetries
	if len(ocspStaple) > 0 {
		// Don't retry if stapled
		retries = 1
	}

	var (
		encoded []byte
		resp    *ocsp.Response
		err     error
	)
	for i := 0; i < retries; i++ {
		encoded = ocspStaple
		if len(encoded) == 0 {
			encoded, err = fetchOCSP(leaf, issuer)
			if err != nil {
				result.err = err
				return result
			}
		}

		resp, err = parseAndVerifyOCSPResponse(encoded, leaf, issuer, time.Now())
		if err == nil {
			result.response = resp
			return result
		}
	}

	result.err = err
	return result
}

// checkOCSPForChains runs an OCSP check for every validated path and retains
// the per-path result. The returned aggregate is independent of path ordering:
// an authoritative status obtained on any path wins over per-path errors, and
// the strongest status (revoked > unknown > good) is reported.
func checkOCSPForChains(chains [][]*x509.Certificate, ocspStaple []byte) ([]chainOCSPResult, chainOCSPResult) {
	results := make([]chainOCSPResult, 0, len(chains))
	for _, chain := range chains {
		results = append(results, checkOCSP(chain, ocspStaple))
	}
	return results, aggregateOCSPResults(results)
}

// aggregateOCSPResults collapses per-path results into a single, deterministic
// conclusion. A response that validates on any path is more trustworthy than a
// failure on another path (a stapled response, for example, is only valid for
// one of several cross-signed paths); statuses are ranked by severity so that
// reordering the input paths cannot change the conclusion.
func aggregateOCSPResults(results []chainOCSPResult) chainOCSPResult {
	statusRank := map[int]int{
		ocsp.Revoked: 3,
		ocsp.Unknown: 2,
		ocsp.Good:    1,
	}

	bestRank := 0
	var best *chainOCSPResult
	anyStapled := false
	sawSkipped := false
	errorMessages := []string{}
	seenErrors := map[string]bool{}

	for i := range results {
		r := &results[i]
		if r.stapled {
			anyStapled = true
		}
		switch {
		case r.response != nil:
			if rank := statusRank[r.response.Status]; rank > bestRank {
				bestRank = rank
				best = r
			}
		case r.skipped:
			sawSkipped = true
		case r.err != nil:
			if msg := r.err.Error(); !seenErrors[msg] {
				seenErrors[msg] = true
				errorMessages = append(errorMessages, msg)
			}
		}
	}

	if best != nil {
		return chainOCSPResult{response: best.response, stapled: best.stapled, issuerCN: best.issuerCN}
	}
	if len(errorMessages) > 0 {
		// Pick deterministically, so reordering paths does not change the
		// reported error.
		sort.Strings(errorMessages)
		return chainOCSPResult{err: errors.New(errorMessages[0]), stapled: anyStapled}
	}
	if sawSkipped {
		return chainOCSPResult{skipped: true, err: errSkippedRevocationCheck, stapled: anyStapled}
	}
	return chainOCSPResult{skipped: true, err: errSkippedRevocationCheck}
}

// strictOCSPVerificationError enforces the explicit strict revocation policy:
// only a current, authoritative "good" response passes. A trusted "revoked"
// status always fails, as does anything that merely fails to prove goodness
// (unknown, missing, expired, malformed, or from an unauthorized responder).
func strictOCSPVerificationError(result chainOCSPResult) error {
	if result.response != nil {
		switch result.response.Status {
		case ocsp.Good:
			return nil
		case ocsp.Revoked:
			reason := revocationReasonDescription[result.response.RevocationReason]
			if reason == "" {
				reason = "Unknown"
			}
			return fmt.Errorf(
				"strict OCSP policy: certificate was revoked at %s (reason: %s)",
				result.response.RevokedAt.Format(time.RFC822), reason)
		default:
			return errors.New("strict OCSP policy: OCSP responder returned an unknown certificate status")
		}
	}
	if result.skipped {
		return errors.New("strict OCSP policy: no OCSP revocation status is available for this certificate")
	}
	return fmt.Errorf("strict OCSP policy: unable to obtain a current OCSP status: %s", result.err)
}

// parseAndVerifyOCSPResponse parses a DER-encoded OCSP response and verifies
// that its conclusion may safely be attributed to the given leaf certificate:
//   - the response must contain a status whose serial number matches the leaf,
//     signed by the leaf's issuer (or a responder authorized by that issuer);
//   - the CertID (issuer name/key hashes) must bind to the given leaf/issuer;
//   - a delegated responder certificate must carry id-kp-OCSPSigning and be
//     within its validity period;
//   - the response must be current (thisUpdate/nextUpdate window).
func parseAndVerifyOCSPResponse(raw []byte, leaf, issuer *x509.Certificate, now time.Time) (*ocsp.Response, error) {
	// ParseResponseForCert rejects OCSP error responses, selects the
	// SingleResponse matching the leaf's serial number, and verifies the
	// signature (directly against the issuer, or against an embedded
	// delegated responder certificate which must itself be signed by the
	// issuer).
	response, err := ocsp.ParseResponseForCert(raw, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("error parsing OCSP response for certificate (serial %s): %w", leaf.SerialNumber, err)
	}

	if err := verifyOCSPCertID(raw, leaf, issuer, response.IssuerHash); err != nil {
		return nil, err
	}
	if err := verifyOCSPResponderAuthorization(response, issuer, now); err != nil {
		return nil, err
	}
	if err := verifyOCSPTimeliness(response, now); err != nil {
		return nil, err
	}
	return response, nil
}

// verifyOCSPCertID checks the CertID of the response status for the leaf:
// hash algorithm, issuerNameHash and issuerKeyHash must identify exactly the
// leaf/issuer pair being validated. Matching on the serial number alone (which
// is all ParseResponseForCert enforces) is insufficient, because serial
// numbers are only unique within a single CA.
func verifyOCSPCertID(raw []byte, leaf, issuer *x509.Certificate, hash crypto.Hash) error {
	ids, err := extractOCSPCertIDs(raw)
	if err != nil {
		return fmt.Errorf("unable to bind OCSP response to certificate (serial %s): %w", leaf.SerialNumber, err)
	}

	h := hash.New()
	h.Write(issuer.RawSubject)
	expectedNameHash := h.Sum(nil)

	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return fmt.Errorf("unable to bind OCSP response to issuer %s: %w", PrintCommonName(issuer.Subject), err)
	}
	keyHash := hash.New()
	keyHash.Write(spki.PublicKey.Bytes)
	expectedKeyHash := keyHash.Sum(nil)

	for _, id := range ids {
		if id.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			continue
		}
		if !bytes.Equal(id.IssuerNameHash, expectedNameHash) || !bytes.Equal(id.IssuerKeyHash, expectedKeyHash) {
			return fmt.Errorf(
				"OCSP response CertID does not match issuer %s of certificate (serial %s)",
				PrintCommonName(issuer.Subject), leaf.SerialNumber)
		}
		return nil
	}
	return fmt.Errorf("OCSP response does not contain a status for certificate (serial %s)", leaf.SerialNumber)
}

// verifyOCSPResponderAuthorization checks delegated OCSP responders per
// RFC 6960 section 4.2.2.2.1: the embedded responder certificate must be issued
// by the certificate's issuer, carry the id-kp-OCSPSigning extended key usage,
// and be within its validity period. The issuer must also explicitly allow
// delegation through its own EKU extension (no EKU extension means unrestricted).
func verifyOCSPResponderAuthorization(response *ocsp.Response, issuer *x509.Certificate, now time.Time) error {
	if response.Certificate == nil {
		// The response was signed directly by the issuing CA; its signature
		// has already been verified by ParseResponseForCert.
		return nil
	}
	responder := response.Certificate

	if !certHasExtKeyUsage(responder, x509.ExtKeyUsageOCSPSigning) {
		return fmt.Errorf(
			"OCSP responder certificate %s is not authorized to sign OCSP responses (missing id-kp-OCSPSigning extended key usage)",
			PrintCommonName(responder.Subject))
	}
	if len(issuer.ExtKeyUsage) > 0 &&
		!certHasExtKeyUsage(issuer, x509.ExtKeyUsageOCSPSigning) &&
		!certHasExtKeyUsage(issuer, x509.ExtKeyUsageAny) {
		return fmt.Errorf(
			"OCSP issuer %s does not delegate OCSP signing (id-kp-OCSPSigning absent from issuer extended key usage)",
			PrintCommonName(issuer.Subject))
	}
	if now.Add(ocspTimingSkew).Before(responder.NotBefore) {
		return fmt.Errorf("OCSP responder certificate %s is not valid before %s",
			PrintCommonName(responder.Subject), responder.NotBefore.Format(time.RFC822))
	}
	if now.Add(-ocspTimingSkew).After(responder.NotAfter) {
		return fmt.Errorf("OCSP responder certificate %s expired on %s",
			PrintCommonName(responder.Subject), responder.NotAfter.Format(time.RFC822))
	}
	return nil
}

// verifyOCSPTimeliness checks that the response falls within its declared
// validity window (RFC 6960 section 2.4). A response without nextUpdate gives
// no freshness guarantee and is therefore not accepted as proof of status.
func verifyOCSPTimeliness(response *ocsp.Response, now time.Time) error {
	if !response.ThisUpdate.IsZero() && now.Add(ocspTimingSkew).Before(response.ThisUpdate) {
		return fmt.Errorf("OCSP response is not yet valid (thisUpdate: %s)", response.ThisUpdate.Format(time.RFC822))
	}
	if response.NextUpdate.IsZero() {
		return errors.New("OCSP response is missing nextUpdate and cannot be proven current")
	}
	if now.Add(-ocspTimingSkew).After(response.NextUpdate) {
		return fmt.Errorf("OCSP response expired at %s", response.NextUpdate.Format(time.RFC822))
	}
	return nil
}

func certHasExtKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == usage {
			return true
		}
	}
	return false
}

// Minimal ASN.1 description of an OCSP response (RFC 6960 Appendix A), used to
// read the CertID(s) without relying on unexported parts of golang.org/x/crypto.
// Only fields needed for CertID verification are modeled; trailing elements
// are ignored by the decoder.
type (
	ocspResponseEnvelopeASN1 struct {
		Status        asn1.Enumerated
		ResponseBytes asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}

	ocspResponseBytesASN1 struct {
		ResponseType asn1.ObjectIdentifier
		Response     []byte
	}

	ocspBasicResponseASN1 struct {
		TBSResponseData    ocspResponseDataASN1
		SignatureAlgorithm asn1.RawValue
		Signature          asn1.BitString
		Certificates       asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}

	ocspResponseDataASN1 struct {
		Version            int `asn1:"explicit,tag:0,optional,default:0"`
		ResponderID        asn1.RawValue
		ProducedAt         time.Time `asn1:"generalized"`
		Responses          []ocspSingleResponseASN1
		ResponseExtensions asn1.RawValue `asn1:"explicit,tag:1,optional"`
	}

	ocspSingleResponseASN1 struct {
		CertID ocspCertIDASN1
	}

	ocspCertIDASN1 struct {
		HashAlgorithm  asn1.RawValue
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		SerialNumber   *big.Int
	}
)

// extractOCSPCertIDs returns every CertID carried by a DER-encoded, successful
// OCSP response.
func extractOCSPCertIDs(raw []byte) ([]ocspCertIDASN1, error) {
	var envelope ocspResponseEnvelopeASN1
	if _, err := asn1.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.ResponseBytes.Bytes) == 0 {
		return nil, errors.New("OCSP response contains no response bytes")
	}

	var responseBytes ocspResponseBytesASN1
	if _, err := asn1.Unmarshal(envelope.ResponseBytes.Bytes, &responseBytes); err != nil {
		return nil, err
	}

	var basic ocspBasicResponseASN1
	if _, err := asn1.Unmarshal(responseBytes.Response, &basic); err != nil {
		return nil, err
	}
	if len(basic.TBSResponseData.Responses) == 0 {
		return nil, errors.New("OCSP response contains no certificate statuses")
	}

	ids := make([]ocspCertIDASN1, 0, len(basic.TBSResponseData.Responses))
	for _, single := range basic.TBSResponseData.Responses {
		ids = append(ids, single.CertID)
	}
	return ids, nil
}

func fetchOCSP(cert, issuer *x509.Certificate) ([]byte, error) {
	encoded, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failure building request: %s", err)
	}

	// Try all the OCSP servers listed in the certificate
	var lastError error
	for _, server := range cert.OCSPServer {
		// We try both GET and POST requests, because some servers are janky.
		var reqs []*http.Request
		if len(encoded) < 255 {
			// GET only supported for requests with small payloads, so we can stash
			// them in the path. RFC says 255 bytes encoded, but doesn't mention if that
			// refers to the DER-encoded payload before or after base64 is applied. We
			// just assume it's the former and try both GET and POST in case one fails.
			req, err := buildOCSPwithGET(server, encoded)
			if err != nil {
				lastError = err
				continue
			}
			reqs = append(reqs, req)
		}

		// POST should always be supported, but some servers don't like it
		req, err := buildOCSPwithPOST(server, encoded)
		if err != nil {
			lastError = err
			continue
		}
		reqs = append(reqs, req)

		for _, req := range reqs {
			body, err := func() ([]byte, error) {
				resp, err := ocspHttpClient.Do(req)
				if err != nil {
					return nil, err
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("unexpected status code, got: %s", resp.Status)
				}

				return io.ReadAll(resp.Body)
			}()
			if err != nil {
				lastError = err
				continue
			}

			return body, nil
		}
	}

	return nil, lastError
}

func buildOCSPwithPOST(server string, encoded []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", server, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	err = req.Write(bytes.NewBuffer(encoded))
	if err != nil {
		return nil, err
	}

	return req, nil
}

func buildOCSPwithGET(server string, encoded []byte) (*http.Request, error) {
	// https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1
	// GET {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
	url := fmt.Sprintf("%s/%s", server, base64.StdEncoding.EncodeToString(encoded))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}
