// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package oss

import (
	"fmt"
	"log"

	"github.com/alibabacloud-go/tea/tea"
	credsgo "github.com/aliyun/credentials-go/credentials"
)

// supportedCredentialTypes lists all credential_type values supported by this backend.
// bearer and rsa_key_pair are intentionally excluded: bearer is not usable by OSS/OTS
// (which require AK/SK), and rsa_key_pair is deprecated by credentials-go.
var supportedCredentialTypes = map[string]struct{}{
	"access_key":      {},
	"sts":             {},
	"ecs_ram_role":    {},
	"ram_role_arn":    {},
	"oidc_role_arn":   {},
	"credentials_uri": {},
}

// getCredentialsFromCredentialsGo builds a credentials-go credential from the
// `credentials` block configuration (the map[string]interface{} returned by
// ResourceData.Get on the TypeList block) and returns the resolved
// AccessKeyId / AccessKeySecret / SecurityToken.
//
// When credential_type is empty it falls back to the credentials-go default provider
// chain (env vars -> OIDC -> ~/.aliyun/config.json -> ~/.alibabacloud/credentials ->
// ECS metadata -> credentials URI).
//
// region is intentionally NOT resolved here; the caller reuses the existing `region`
// schema field for endpoint / OTS resolution so backend.go stays unchanged there.
func getCredentialsFromCredentialsGo(cfg map[string]interface{}) (accessKey, secretKey, securityToken string, err error) {
	credType := getCredString(cfg, "credential_type")

	// Emit a debug log whenever the credentials-go path is taken, including the
	// effective config values that may have been sourced from environment
	// variables (the env var name is shown in parentheses after each field).
	// Secret values (access_key / secret_key / security_token) are only reported
	// as set/unset to avoid leaking credentials into the log.
	logCredType := credType
	if logCredType == "" {
		logCredType = "default_provider_chain"
	}
	log.Printf("[DEBUG] oss backend: authenticating via credentials-go SDK (credential_type=%s). "+
		"Effective config (env var source in parens): "+
		"access_key_set=%t (ALICLOUD_ACCESS_KEY/ALIBABA_CLOUD_ACCESS_KEY_ID), "+
		"secret_key_set=%t, security_token_set=%t (ALIBABA_CLOUD_SECURITY_TOKEN), "+
		"ecs_role_name=%q (ALICLOUD_ECS_ROLE_NAME/ALIBABA_CLOUD_ECS_METADATA), "+
		"oidc_provider_arn=%q (ALIBABA_CLOUD_OIDC_PROVIDER_ARN), "+
		"oidc_token_file_path=%q (ALIBABA_CLOUD_OIDC_TOKEN_FILE), "+
		"assume_role_role_arn=%q (ALICLOUD_ASSUME_ROLE_ARN/ALIBABA_CLOUD_ROLE_ARN), "+
		"assume_role_session_name=%q (ALICLOUD_ASSUME_ROLE_SESSION_NAME/ALIBABA_CLOUD_ROLE_SESSION_NAME), "+
		"external_id=%q, sts_endpoint=%q (ALICLOUD_STS_ENDPOINT/ALIBABA_CLOUD_STS_ENDPOINT), "+
		"credentials_uri_set=%t (ALIBABA_CLOUD_CREDENTIALS_URI), disable_imds_v1=%t (ALIBABA_CLOUD_IMDSV1_DISABLED)",
		logCredType,
		getCredString(cfg, "access_key") != "",
		getCredString(cfg, "secret_key") != "",
		getCredString(cfg, "security_token") != "",
		getCredString(cfg, "ecs_role_name"),
		getCredString(cfg, "oidc_provider_arn"),
		getCredString(cfg, "oidc_token_file_path"),
		getCredString(cfg, "assume_role_role_arn"),
		getCredString(cfg, "assume_role_session_name"),
		getCredString(cfg, "external_id"),
		getCredString(cfg, "sts_endpoint"),
		getCredString(cfg, "credentials_uri") != "",
		getCredBool(cfg, "disable_imds_v1"),
	)

	if credType == "" {
		return resolveCredential(nil)
	}

	if _, ok := supportedCredentialTypes[credType]; !ok {
		return "", "", "", fmt.Errorf("unsupported credential_type %q, supported: access_key, sts, ecs_ram_role, ram_role_arn, oidc_role_arn, credentials_uri, or leave empty for default provider chain", credType)
	}

	c := new(credsgo.Config).SetType(credType)

	// Common fields shared by several types.
	accessKeyID := getCredString(cfg, "access_key")
	accessKeySecret := getCredString(cfg, "secret_key")
	token := getCredString(cfg, "security_token")
	stsEndpoint := getCredString(cfg, "sts_endpoint")

	switch credType {
	case "access_key":
		if accessKeyID == "" || accessKeySecret == "" {
			return "", "", "", fmt.Errorf("credential_type=access_key requires access_key and secret_key")
		}
		c.SetAccessKeyId(accessKeyID).SetAccessKeySecret(accessKeySecret)

	case "sts":
		if accessKeyID == "" || accessKeySecret == "" || token == "" {
			return "", "", "", fmt.Errorf("credential_type=sts requires access_key, secret_key and security_token")
		}
		c.SetAccessKeyId(accessKeyID).
			SetAccessKeySecret(accessKeySecret).
			SetSecurityToken(token)

	case "ecs_ram_role":
		if role := getCredString(cfg, "ecs_role_name"); role != "" {
			c.SetRoleName(role)
		}
		if getCredBool(cfg, "disable_imds_v1") {
			c.SetDisableIMDSv1(true)
		}

	case "ram_role_arn":
		if accessKeyID == "" || accessKeySecret == "" {
			return "", "", "", fmt.Errorf("credential_type=ram_role_arn requires access_key and secret_key")
		}
		c.SetAccessKeyId(accessKeyID).
			SetAccessKeySecret(accessKeySecret)
		if token != "" {
			c.SetSecurityToken(token)
		}
		applyRoleArnConfig(cfg, c, stsEndpoint)

	case "oidc_role_arn":
		if providerArn := getCredString(cfg, "oidc_provider_arn"); providerArn != "" {
			c.SetOIDCProviderArn(providerArn)
		}
		if tokenFile := getCredString(cfg, "oidc_token_file_path"); tokenFile != "" {
			c.SetOIDCTokenFilePath(tokenFile)
		}
		applyRoleArnConfig(cfg, c, stsEndpoint)

	case "credentials_uri":
		uri := getCredString(cfg, "credentials_uri")
		// credentials-go also reads ALIBABA_CLOUD_CREDENTIALS_URI inside SetURLCredential
		// when the value is empty, so we call it unconditionally.
		c.SetURLCredential(uri)
	}

	return resolveCredential(c)
}

// applyRoleArnConfig fills the role-arn-related setters shared by ram_role_arn and
// oidc_role_arn. The assume_role_* block fields are reused for these types since they
// carry the same semantics (the role to assume).
func applyRoleArnConfig(cfg map[string]interface{}, c *credsgo.Config, stsEndpoint string) {
	if v := getCredString(cfg, "assume_role_role_arn"); v != "" {
		c.SetRoleArn(v)
	}
	if v := getCredString(cfg, "assume_role_session_name"); v != "" {
		c.SetRoleSessionName(v)
	}
	if v := getCredString(cfg, "assume_role_policy"); v != "" {
		c.SetPolicy(v)
	}
	if v := getCredInt(cfg, "assume_role_session_expiration"); v != 0 {
		c.SetRoleSessionExpiration(v)
	}
	if v := getCredString(cfg, "external_id"); v != "" {
		c.SetExternalId(v)
	}
	if stsEndpoint != "" {
		c.SetSTSEndpoint(stsEndpoint)
	}
}

// getCredString reads a string field from the credentials block map, returning ""
// when the key is absent or nil. ResourceData normally populates every schema field
// (including defaults), but this guard keeps the code robust against an explicitly
// nil entry.
func getCredString(cfg map[string]interface{}, key string) string {
	if v, ok := cfg[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// getCredBool reads a bool field from the credentials block map.
func getCredBool(cfg map[string]interface{}, key string) bool {
	if v, ok := cfg[key]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// getCredInt reads an int field from the credentials block map.
func getCredInt(cfg map[string]interface{}, key string) int {
	if v, ok := cfg[key]; ok && v != nil {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}

// resolveCredential constructs the credential, calls GetCredential and dereferences the
// pointer fields into plain strings. region is left untouched.
func resolveCredential(cfg *credsgo.Config) (accessKey, secretKey, securityToken string, err error) {
	cred, err := credsgo.NewCredential(cfg)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to build credentials-go credential: %w", err)
	}
	model, err := cred.GetCredential()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get credential from credentials-go: %w", err)
	}
	if model == nil {
		return "", "", "", fmt.Errorf("credentials-go returned an empty credential model")
	}

	accessKey = tea.StringValue(model.AccessKeyId)
	secretKey = tea.StringValue(model.AccessKeySecret)
	securityToken = tea.StringValue(model.SecurityToken)

	if accessKey == "" || secretKey == "" {
		return "", "", "", fmt.Errorf("credentials-go returned an empty AccessKeyId / AccessKeySecret (credential type: %s)", tea.StringValue(model.Type))
	}
	return accessKey, secretKey, securityToken, nil
}
