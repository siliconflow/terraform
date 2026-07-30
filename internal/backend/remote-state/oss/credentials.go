// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package oss

import (
	"fmt"

	"github.com/alibabacloud-go/tea/tea"
	credsgo "github.com/aliyun/credentials-go/credentials"

	"github.com/hashicorp/terraform/internal/legacy/helper/schema"
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

// getCredentialsFromCredentialsGo builds a credentials-go credential from the backend
// schema and returns the resolved AccessKeyId / AccessKeySecret / SecurityToken.
//
// When credential_type is empty it falls back to the credentials-go default provider
// chain (env vars -> OIDC -> ~/.aliyun/config.json -> ~/.alibabacloud/credentials ->
// ECS metadata -> credentials URI).
//
// region is intentionally NOT resolved here; the caller reuses the existing `region`
// schema field for endpoint / OTS resolution so backend.go stays unchanged there.
func getCredentialsFromCredentialsGo(d *schema.ResourceData) (accessKey, secretKey, securityToken string, err error) {
	credType := d.Get("credential_type").(string)

	if credType == "" {
		return resolveCredential(nil)
	}

	if _, ok := supportedCredentialTypes[credType]; !ok {
		return "", "", "", fmt.Errorf("unsupported credential_type %q, supported: access_key, sts, ecs_ram_role, ram_role_arn, oidc_role_arn, credentials_uri, or leave empty for default provider chain", credType)
	}

	cfg := new(credsgo.Config).SetType(credType)

	// Common fields shared by several types.
	accessKeyID := d.Get("access_key").(string)
	accessKeySecret := d.Get("secret_key").(string)
	token := d.Get("security_token").(string)
	stsEndpoint := d.Get("sts_endpoint").(string)

	switch credType {
	case "access_key":
		if accessKeyID == "" || accessKeySecret == "" {
			return "", "", "", fmt.Errorf("credential_type=access_key requires access_key and secret_key")
		}
		cfg.SetAccessKeyId(accessKeyID).SetAccessKeySecret(accessKeySecret)

	case "sts":
		if accessKeyID == "" || accessKeySecret == "" || token == "" {
			return "", "", "", fmt.Errorf("credential_type=sts requires access_key, secret_key and security_token")
		}
		cfg.SetAccessKeyId(accessKeyID).
			SetAccessKeySecret(accessKeySecret).
			SetSecurityToken(token)

	case "ecs_ram_role":
		if role := d.Get("ecs_role_name").(string); role != "" {
			cfg.SetRoleName(role)
		}
		if d.Get("disable_imds_v1").(bool) {
			cfg.SetDisableIMDSv1(true)
		}

	case "ram_role_arn":
		if accessKeyID == "" || accessKeySecret == "" {
			return "", "", "", fmt.Errorf("credential_type=ram_role_arn requires access_key and secret_key")
		}
		cfg.SetAccessKeyId(accessKeyID).
			SetAccessKeySecret(accessKeySecret)
		if token != "" {
			cfg.SetSecurityToken(token)
		}
		applyRoleArnConfig(d, cfg, stsEndpoint)

	case "oidc_role_arn":
		if providerArn := d.Get("oidc_provider_arn").(string); providerArn != "" {
			cfg.SetOIDCProviderArn(providerArn)
		}
		if tokenFile := d.Get("oidc_token_file_path").(string); tokenFile != "" {
			cfg.SetOIDCTokenFilePath(tokenFile)
		}
		applyRoleArnConfig(d, cfg, stsEndpoint)

	case "credentials_uri":
		uri := d.Get("credentials_uri").(string)
		if uri == "" {
			// credentials-go also reads ALIBABA_CLOUD_CREDENTIALS_URI inside SetURLCredential
			// when the value is empty, so we call it unconditionally.
		}
		cfg.SetURLCredential(uri)
	}

	return resolveCredential(cfg)
}

// applyRoleArnConfig fills the role-arn-related setters shared by ram_role_arn and
// oidc_role_arn. The assume_role_* schema fields are reused for these types since they
// carry the same semantics (the role to assume).
func applyRoleArnConfig(d *schema.ResourceData, cfg *credsgo.Config, stsEndpoint string) {
	if v := d.Get("assume_role_role_arn").(string); v != "" {
		cfg.SetRoleArn(v)
	}
	if v := d.Get("assume_role_session_name").(string); v != "" {
		cfg.SetRoleSessionName(v)
	}
	if v := d.Get("assume_role_policy").(string); v != "" {
		cfg.SetPolicy(v)
	}
	if v, ok := d.GetOk("assume_role_session_expiration"); ok {
		cfg.SetRoleSessionExpiration(v.(int))
	}
	if v := d.Get("external_id").(string); v != "" {
		cfg.SetExternalId(v)
	}
	if stsEndpoint != "" {
		cfg.SetSTSEndpoint(stsEndpoint)
	}
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
