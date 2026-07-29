// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: BUSL-1.1

package oss

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"strings"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/aliyun/aliyun-tablestore-go-sdk/tablestore"
	"github.com/hashicorp/terraform/internal/backend"
	"github.com/hashicorp/terraform/internal/configs/hcl2shim"
)

// verify that we are doing ACC tests or the OSS tests specifically
func testACC(t *testing.T) {
	skip := os.Getenv("TF_ACC") == "" && os.Getenv("TF_OSS_TEST") == ""
	if skip {
		t.Log("oss backend tests require setting TF_ACC or TF_OSS_TEST")
		t.Skip()
	}
	if skip {
		t.Fatal("oss backend tests require setting ALICLOUD_ACCESS_KEY or ALICLOUD_ACCESS_KEY_ID")
	}
	if os.Getenv("ALICLOUD_REGION") == "" {
		os.Setenv("ALICLOUD_REGION", "cn-beijing")
	}
}

func TestBackend_impl(t *testing.T) {
	var _ backend.Backend = new(Backend)
}

func TestBackendConfig(t *testing.T) {
	testACC(t)
	config := map[string]interface{}{
		"region":              "cn-beijing",
		"bucket":              "terraform-backend-oss-test",
		"prefix":              "mystate",
		"key":                 "first.tfstate",
		"tablestore_endpoint": "https://terraformstate.cn-beijing.ots.aliyuncs.com",
		"tablestore_table":    "TableStore",
	}

	b := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(config)).(*Backend)

	if !strings.HasPrefix(b.ossClient.Config.Endpoint, "https://oss-cn-beijing") {
		t.Fatalf("Incorrect region was provided")
	}
	if b.bucketName != "terraform-backend-oss-test" {
		t.Fatalf("Incorrect bucketName was provided")
	}
	if b.statePrefix != "mystate" {
		t.Fatalf("Incorrect state file path was provided")
	}
	if b.stateKey != "first.tfstate" {
		t.Fatalf("Incorrect keyName was provided")
	}

	if b.ossClient.Config.AccessKeyID == "" {
		t.Fatalf("No Access Key Id was provided")
	}
	if b.ossClient.Config.AccessKeySecret == "" {
		t.Fatalf("No Secret Access Key was provided")
	}
}

func TestBackendConfigWorkSpace(t *testing.T) {
	testACC(t)
	bucketName := fmt.Sprintf("terraform-backend-oss-test-%d", rand.Intn(1000))
	config := map[string]interface{}{
		"region":              "cn-beijing",
		"bucket":              bucketName,
		"prefix":              "mystate",
		"key":                 "first.tfstate",
		"tablestore_endpoint": "https://terraformstate.cn-beijing.ots.aliyuncs.com",
		"tablestore_table":    "TableStore",
	}

	b := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(config)).(*Backend)
	createOSSBucket(t, b.ossClient, bucketName)
	defer deleteOSSBucket(t, b.ossClient, bucketName)
	if _, diags := b.Workspaces(); diags.HasErrors() {
		t.Fatal(diags.Err().Error())
	}
	if !strings.HasPrefix(b.ossClient.Config.Endpoint, "https://oss-cn-beijing") {
		t.Fatalf("Incorrect region was provided")
	}
	if b.bucketName != bucketName {
		t.Fatalf("Incorrect bucketName was provided")
	}
	if b.statePrefix != "mystate" {
		t.Fatalf("Incorrect state file path was provided")
	}
	if b.stateKey != "first.tfstate" {
		t.Fatalf("Incorrect keyName was provided")
	}

	if b.ossClient.Config.AccessKeyID == "" {
		t.Fatalf("No Access Key Id was provided")
	}
	if b.ossClient.Config.AccessKeySecret == "" {
		t.Fatalf("No Secret Access Key was provided")
	}
}

func TestBackendConfigProfile(t *testing.T) {
	testACC(t)
	config := map[string]interface{}{
		"region":              "cn-beijing",
		"bucket":              "terraform-backend-oss-test",
		"prefix":              "mystate",
		"key":                 "first.tfstate",
		"tablestore_endpoint": "https://terraformstate.cn-beijing.ots.aliyuncs.com",
		"tablestore_table":    "TableStore",
		"profile":             "default",
	}

	b := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(config)).(*Backend)

	if !strings.HasPrefix(b.ossClient.Config.Endpoint, "https://oss-cn-beijing") {
		t.Fatalf("Incorrect region was provided")
	}
	if b.bucketName != "terraform-backend-oss-test" {
		t.Fatalf("Incorrect bucketName was provided")
	}
	if b.statePrefix != "mystate" {
		t.Fatalf("Incorrect state file path was provided")
	}
	if b.stateKey != "first.tfstate" {
		t.Fatalf("Incorrect keyName was provided")
	}

	if b.ossClient.Config.AccessKeyID == "" {
		t.Fatalf("No Access Key Id was provided")
	}
	if b.ossClient.Config.AccessKeySecret == "" {
		t.Fatalf("No Secret Access Key was provided")
	}
}

// TestBackendConfigOIDCFields verifies the new oidc_* schema fields parse and
// validate cleanly. It exercises only PrepareConfig and does not touch the
// network, so it runs without TF_ACC.
func TestBackendConfigOIDCFields(t *testing.T) {
	cfg := hcl2shim.HCL2ValueFromConfigValue(map[string]interface{}{
		"region":                    "cn-beijing",
		"bucket":                    "terraform-backend-oss-test",
		"prefix":                    "mystate",
		"key":                       "first.tfstate",
		"oidc_provider_arn":         "acs:ram::123456789012****:oidc-provider/test",
		"oidc_token_file_path":      "/var/run/secrets/oidc/token",
		"oidc_role_arn":             "acs:ram::123456789012****:role/test",
		"oidc_session_name":         "terraform",
		"oidc_policy":               `{"Version":"1"}`,
		"oidc_session_expiration":   3600,
	})
	if _, results := New().PrepareConfig(cfg); results.HasErrors() {
		t.Fatalf("unexpected config validation error: %v", results.Err())
	}
}

// TestBackendConfigOIDCExpirationInvalid ensures oidc_session_expiration
// rejects values outside the 900-3600 range, mirroring
// assume_role_session_expiration validation.
func TestBackendConfigOIDCExpirationInvalid(t *testing.T) {
	for _, v := range []int{899, 3601} {
		cfg := hcl2shim.HCL2ValueFromConfigValue(map[string]interface{}{
			"region":                  "cn-beijing",
			"bucket":                  "terraform-backend-oss-test",
			"oidc_session_expiration": v,
		})
		_, results := New().PrepareConfig(cfg)
		if !results.HasErrors() {
			t.Fatalf("expected validation error for oidc_session_expiration=%d", v)
		}
	}
}

// TestGetOIDCCredentialBuildError verifies that getOIDCCredential surfaces
// config-build errors from credentials-go (here: an empty role ARN) without
// reaching the network. credentials-go's OIDC provider builder errors during
// Build() before any HTTP call is made.
func TestGetOIDCCredentialBuildError(t *testing.T) {
	// Unset the env vars credentials-go would otherwise use as fallbacks, so
	// the empty role ARN deterministically produces a build error.
	for _, k := range []string{"ALIBABA_CLOUD_OIDC_TOKEN_FILE", "ALIBABA_CLOUD_OIDC_PROVIDER_ARN", "ALIBABA_CLOUD_ROLE_ARN"} {
		old, had := os.LookupEnv(k)
		os.Unsetenv(k)
		if had {
			defer os.Setenv(k, old)
		}
	}

	_, _, _, err := getOIDCCredential(
		"",                               // roleArn: empty -> build error
		"acs:ram::123456789012****:oidc-provider/test",
		"/var/run/secrets/oidc/token",
		"terraform", "", "", 3600,
	)
	if err == nil {
		t.Fatal("expected error when role ARN is empty, got nil")
	}
}

func TestBackendConfig_invalidKey(t *testing.T) {
	testACC(t)
	cfg := hcl2shim.HCL2ValueFromConfigValue(map[string]interface{}{
		"region":              "cn-beijing",
		"bucket":              "terraform-backend-oss-test",
		"prefix":              "/leading-slash",
		"name":                "/test.tfstate",
		"tablestore_endpoint": "https://terraformstate.cn-beijing.ots.aliyuncs.com",
		"tablestore_table":    "TableStore",
	})

	_, results := New().PrepareConfig(cfg)
	if !results.HasErrors() {
		t.Fatal("expected config validation error")
	}
}

func TestBackend(t *testing.T) {
	testACC(t)

	bucketName := fmt.Sprintf("terraform-remote-oss-test-%x", time.Now().Unix())
	statePrefix := "multi/level/path/"

	b1 := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(map[string]interface{}{
		"bucket": bucketName,
		"prefix": statePrefix,
	})).(*Backend)

	b2 := backend.TestBackendConfig(t, New(), backend.TestWrapConfig(map[string]interface{}{
		"bucket": bucketName,
		"prefix": statePrefix,
	})).(*Backend)

	createOSSBucket(t, b1.ossClient, bucketName)
	defer deleteOSSBucket(t, b1.ossClient, bucketName)

	backend.TestBackendStates(t, b1)
	backend.TestBackendStateLocks(t, b1, b2)
	backend.TestBackendStateForceUnlock(t, b1, b2)
}

func createOSSBucket(t *testing.T, ossClient *oss.Client, bucketName string) {
	// Be clear about what we're doing in case the user needs to clean this up later.
	if err := ossClient.CreateBucket(bucketName); err != nil {
		t.Fatal("failed to create test OSS bucket:", err)
	}
}

func deleteOSSBucket(t *testing.T, ossClient *oss.Client, bucketName string) {
	warning := "WARNING: Failed to delete the test OSS bucket. It may have been left in your Alibaba Cloud account and may incur storage charges. (error was %s)"

	// first we have to get rid of the env objects, or we can't delete the bucket
	bucket, err := ossClient.Bucket(bucketName)
	if err != nil {
		t.Fatal("Error getting bucket:", err)
		return
	}
	objects, err := bucket.ListObjects()
	if err != nil {
		t.Logf(warning, err)
		return
	}
	for _, obj := range objects.Objects {
		if err := bucket.DeleteObject(obj.Key); err != nil {
			// this will need cleanup no matter what, so just warn and exit
			t.Logf(warning, err)
			return
		}
	}

	if err := ossClient.DeleteBucket(bucketName); err != nil {
		t.Logf(warning, err)
	}
}

// create the tablestore table, and wait until we can query it.
func createTablestoreTable(t *testing.T, otsClient *tablestore.TableStoreClient, tableName string) {
	tableMeta := new(tablestore.TableMeta)
	tableMeta.TableName = tableName
	tableMeta.AddPrimaryKeyColumn(pkName, tablestore.PrimaryKeyType_STRING)

	tableOption := new(tablestore.TableOption)
	tableOption.TimeToAlive = -1
	tableOption.MaxVersion = 1

	reservedThroughput := new(tablestore.ReservedThroughput)

	_, err := otsClient.CreateTable(&tablestore.CreateTableRequest{
		TableMeta:          tableMeta,
		TableOption:        tableOption,
		ReservedThroughput: reservedThroughput,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func deleteTablestoreTable(t *testing.T, otsClient *tablestore.TableStoreClient, tableName string) {
	params := &tablestore.DeleteTableRequest{
		TableName: tableName,
	}
	_, err := otsClient.DeleteTable(params)
	if err != nil {
		t.Logf("WARNING: Failed to delete the test TableStore table %q. It has been left in your Alibaba Cloud account and may incur charges. (error was %s)", tableName, err)
	}
}

func TestGetHttpProxyUrl(t *testing.T) {
	tests := []struct {
		name             string
		rawUrl           string
		httpProxy        string
		httpsProxy       string
		noProxy          string
		expectedProxyURL string
	}{
		{
			name:             "should set proxy using http_proxy environment variable",
			rawUrl:           "http://example.com",
			httpProxy:        "http://foo.bar:3128",
			httpsProxy:       "https://secure.example.com",
			noProxy:          "",
			expectedProxyURL: "http://foo.bar:3128",
		},
		{
			name:             "should set proxy using http_proxy environment variable",
			rawUrl:           "http://example.com",
			httpProxy:        "http://foo.barr",
			httpsProxy:       "https://secure.example.com",
			noProxy:          "",
			expectedProxyURL: "http://foo.barr",
		},
		{
			name:             "should set proxy using https_proxy environment variable",
			rawUrl:           "https://secure.example.com",
			httpProxy:        "http://foo.bar",
			httpsProxy:       "https://foo.bar.com:3128",
			noProxy:          "",
			expectedProxyURL: "https://foo.bar.com:3128",
		},
		{
			name:             "should set proxy using https_proxy environment variable",
			rawUrl:           "https://secure.example.com",
			httpProxy:        "",
			httpsProxy:       "http://foo.baz",
			noProxy:          "",
			expectedProxyURL: "http://foo.baz",
		},
		{
			name:             "should not set http proxy if NO_PROXY contains the host",
			rawUrl:           "http://example.internal",
			httpProxy:        "http://foo.bar:3128",
			httpsProxy:       "",
			noProxy:          "example.internal",
			expectedProxyURL: "",
		},
		{
			name:             "should not set HTTP proxy when NO_PROXY matches the domain with suffix",
			rawUrl:           "http://qqu.example.internal",
			httpProxy:        "http://foo.bar:3128",
			httpsProxy:       "",
			noProxy:          ".example.internal",
			expectedProxyURL: "",
		},
		{
			name:             "should not set https proxy if NO_PROXY contains the host",
			rawUrl:           "https://secure.internal",
			httpProxy:        "",
			httpsProxy:       "https://foo.baz:3128",
			noProxy:          "secure.internal",
			expectedProxyURL: "",
		},
		{
			name:             "should not set https proxy if NO_PROXY matches the domain with suffix",
			rawUrl:           "https://ss.qcsc.secure.internal",
			httpProxy:        "",
			httpsProxy:       "https://foo.baz:3128",
			noProxy:          ".secure.internal",
			expectedProxyURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			t.Setenv("HTTP_PROXY", tt.httpProxy)
			t.Setenv("HTTPS_PROXY", tt.httpsProxy)
			t.Setenv("NO_PROXY", tt.noProxy)

			proxyUrl, err := getHttpProxyUrl(tt.rawUrl)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if tt.expectedProxyURL == "" {
				if proxyUrl != nil {
					t.Fatalf("unexpected proxy  URL, want nil, got: %s", proxyUrl)
				}
			} else {
				if tt.expectedProxyURL != proxyUrl.String() {
					t.Fatalf("unexpected proxy URL, want: %s, got: %s", tt.expectedProxyURL, proxyUrl.String())
				}
			}
		})
	}
}
