package infisical

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// stsRequestBody is the signed STS call Infisical replays to identify the caller.
const stsRequestBody = "Action=GetCallerIdentity&Version=2011-06-15"

const stsContentType = "application/x-www-form-urlencoded; charset=utf-8"

// AwsIamAuth logs a machine identity in with AWS IAM credentials
// (POST /api/v1/auth/aws-auth/login). The client signs an STS
// GetCallerIdentity request with AWS Signature Version 4 and sends it to
// Infisical, which forwards it to AWS STS to verify the caller. Credentials
// left empty are read from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// AWS_SESSION_TOKEN and AWS_REGION / AWS_DEFAULT_REGION.
type AwsIamAuth struct {
	// IdentityID is the machine identity id.
	IdentityID string
	// Region is the STS region (default AWS_REGION, AWS_DEFAULT_REGION, then us-east-1).
	Region string
	// AccessKeyID is the AWS access key id.
	AccessKeyID string
	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey Secret
	// SessionToken is the optional AWS session token (temporary credentials).
	SessionToken Secret
	// OrganizationSlug optionally selects a sub-organization.
	OrganizationSlug string

	// now returns the signing time (tests).
	now func() time.Time
}

// AwsLoginRequest is the login body AwsIamAuth sends (exposed for tests and debugging).
type AwsLoginRequest struct {
	IdentityID           string `json:"identityId"`
	IamHTTPRequestMethod string `json:"iamHttpRequestMethod"`
	// IamRequestBody is base64("Action=GetCallerIdentity&Version=2011-06-15").
	IamRequestBody string `json:"iamRequestBody"`
	// IamRequestHeaders is base64 of the JSON object of the signed headers.
	IamRequestHeaders string `json:"iamRequestHeaders"`
	OrganizationSlug  string `json:"organizationSlug,omitempty"`
}

func (a *AwsIamAuth) credentials() (region, keyID, secret, session string) {
	region, keyID = a.Region, a.AccessKeyID
	secret, session = a.SecretAccessKey.Reveal(), a.SessionToken.Reveal()
	first := func(names ...string) string {
		for _, n := range names {
			if v := os.Getenv(n); v != "" {
				return v
			}
		}
		return ""
	}
	if region == "" {
		region = first("AWS_REGION", "AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	if keyID == "" {
		keyID = first("AWS_ACCESS_KEY_ID")
	}
	if secret == "" {
		secret = first("AWS_SECRET_ACCESS_KEY")
	}
	if session == "" && a.SessionToken.IsZero() && a.AccessKeyID == "" {
		session = first("AWS_SESSION_TOKEN")
	}
	return region, keyID, secret, session
}

// LoginRequest builds the signed login body (no network call).
func (a *AwsIamAuth) LoginRequest() (*AwsLoginRequest, error) {
	const op = "auth.awsIamAuth.login"
	if a.IdentityID == "" {
		return nil, ConfigError(op + ": identityId is required")
	}
	region, keyID, secret, session := a.credentials()
	if keyID == "" || secret == "" {
		return nil, ConfigError(op + ": AWS credentials are required (AccessKeyID/SecretAccessKey or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)")
	}
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	host := "sts." + region + ".amazonaws.com"
	headers := map[string]string{"Host": host, "Content-Type": stsContentType}
	if session != "" {
		headers["X-Amz-Security-Token"] = session
	}
	signed := SignV4(SigV4Request{
		Method: "POST", Host: host, Path: "/", Headers: headers, Body: []byte(stsRequestBody),
		Region: region, Service: "sts", AccessKeyID: keyID, SecretAccessKey: secret, Time: now(),
	})
	signed["Content-Length"] = strconv.Itoa(len(stsRequestBody))
	hdrJSON, err := json.Marshal(signed)
	if err != nil {
		return nil, ValidationError(op, "signed headers cannot be encoded")
	}
	return &AwsLoginRequest{
		IdentityID:           a.IdentityID,
		IamHTTPRequestMethod: "POST",
		IamRequestBody:       base64.StdEncoding.EncodeToString([]byte(stsRequestBody)),
		IamRequestHeaders:    base64.StdEncoding.EncodeToString(hdrJSON),
		OrganizationSlug:     a.OrganizationSlug,
	}, nil
}

// Login implements Authenticator.
func (a *AwsIamAuth) Login(ctx context.Context, c *Client) (*AccessToken, error) {
	body, err := a.LoginRequest()
	if err != nil {
		return nil, err
	}
	_, keyID, secret, session := a.credentials()
	c.rememberSecret(keyID, secret, session)
	return c.tokenCall(ctx, "auth.awsIamAuth.login", "/api/v1/auth/aws-auth/login", body)
}

// String renders the method with the credentials redacted.
func (a *AwsIamAuth) String() string {
	return "AwsIamAuth{IdentityID:" + a.IdentityID + " Region:" + a.Region + " SecretAccessKey:" + Redacted + "}"
}

// --- AWS Signature Version 4 -----------------------------------------------------

// SigV4Request is a request to sign with AWS Signature Version 4.
type SigV4Request struct {
	Method string
	Host   string
	// Path is the URI path ("/" when empty); it must already be URI-encoded.
	Path string
	// Query is the raw query string (already encoded, may be empty).
	Query string
	// Headers are signed in addition to Host and X-Amz-Date.
	Headers map[string]string
	Body    []byte
	Region  string
	Service string
	// AccessKeyID and SecretAccessKey are the signing credentials.
	AccessKeyID     string
	SecretAccessKey string
	Time            time.Time
}

// SignV4 signs r and returns every header to send: the given headers plus
// Host, X-Amz-Date and Authorization.
func SignV4(r SigV4Request) map[string]string {
	t := r.Time.UTC()
	amzDate := t.Format("20060102T150405Z")
	date := t.Format("20060102")
	out := make(map[string]string, len(r.Headers)+3)
	for k, v := range r.Headers {
		out[k] = v
	}
	if _, ok := lookupHeader(out, "host"); !ok {
		out["Host"] = r.Host
	}
	out["X-Amz-Date"] = amzDate

	names := make([]string, 0, len(out))
	values := map[string]string{}
	for k, v := range out {
		lk := strings.ToLower(k)
		names = append(names, lk)
		values[lk] = strings.Join(strings.Fields(v), " ")
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + values[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	path := r.Path
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		r.Method, path, canonicalQuery(r.Query), canonHeaders.String(), signedHeaders, hexSHA256(r.Body),
	}, "\n")
	scope := date + "/" + r.Region + "/" + r.Service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hexSHA256([]byte(canonical))
	key := hmacSHA256([]byte("AWS4"+r.SecretAccessKey), date)
	key = hmacSHA256(key, r.Region)
	key = hmacSHA256(key, r.Service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))
	out["Authorization"] = "AWS4-HMAC-SHA256 Credential=" + r.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + sig
	return out
}

func lookupHeader(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// canonicalQuery sorts the query parameters by name, then value.
func canonicalQuery(q string) string {
	if q == "" {
		return ""
	}
	parts := strings.Split(q, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
