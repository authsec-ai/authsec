package gcp

import "testing"

func TestAssetKind_TicketKindsAreAllReachable(t *testing.T) {
	want := map[string]string{
		"storage.googleapis.com/Bucket":                    "gcs_bucket",
		"bigquery.googleapis.com/Dataset":                  "bq_dataset",
		"bigquery.googleapis.com/Table":                    "bq_table",
		"secretmanager.googleapis.com/Secret":              "secret",
		"cloudkms.googleapis.com/CryptoKey":                "kms_key",
		"cloudkms.googleapis.com/KeyRing":                  "kms_keyring",
		"pubsub.googleapis.com/Topic":                      "pubsub_topic",
		"pubsub.googleapis.com/Subscription":               "pubsub_subscription",
		"run.googleapis.com/Service":                       "run_service",
		"cloudfunctions.googleapis.com/CloudFunction":      "cloud_function",
		"cloudfunctions.googleapis.com/Function":           "cloud_function",
		"artifactregistry.googleapis.com/Repository":       "artifact_repo",
		"sqladmin.googleapis.com/Instance":                 "sql_instance",
		"spanner.googleapis.com/Instance":                  "spanner_instance",
		"iam.googleapis.com/ServiceAccount":                "service_account",
		"cloudresourcemanager.googleapis.com/Project":      "project",
		"cloudresourcemanager.googleapis.com/Folder":       "folder",
		"cloudresourcemanager.googleapis.com/Organization": "organization",
	}
	for asset, kind := range want {
		if got := AssetKind(asset); got != kind {
			t.Errorf("AssetKind(%q) = %q, want %q", asset, got, kind)
		}
	}
}

func TestAssetKind_UnknownIsKeptNotDropped(t *testing.T) {
	if got := AssetKind("somenew.googleapis.com/Widget"); got != KindUnknownGCPAsset {
		t.Fatalf("got %q", got)
	}
}

func TestIsScopeKind(t *testing.T) {
	for _, k := range []string{KindProject, KindFolder, KindOrganization} {
		if !IsScopeKind(k) {
			t.Errorf("%s should be a scope kind", k)
		}
	}
	if IsScopeKind(KindGCSBucket) || IsScopeKind(KindUnknownGCPAsset) {
		t.Error("resource kinds are not scope kinds")
	}
}

func TestResourceSensitivityAndName(t *testing.T) {
	if ResourceSensitivity(KindSecret) != "high" || ResourceSensitivity(KindGCSBucket) != "med" || ResourceSensitivity(KindPubSubTopic) != "low" {
		t.Fatal("sensitivity heuristic changed")
	}
	if ResourceDisplayName("//storage.googleapis.com/projects/_/buckets/iga-public-iam-1") != "iga-public-iam-1" {
		t.Fatal("display name")
	}
}
