package gcp

// TODO(GCP-7): Implement IsServiceDisabled and enable this test
// func TestIsServiceDisabled(t *testing.T) {
// 	yes := []error{
// 		&googleapi.Error{Code: 403, Message: "API keys API has not been used in project 123 before or it is disabled."},
// 		&googleapi.Error{Code: 403, Message: "x", Details: []interface{}{map[string]interface{}{"reason": "SERVICE_DISABLED"}}},
// 		fmt.Errorf("wrapped: %w", &googleapi.Error{Code: 403, Body: `{"error":{"status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`}),
// 	}
// 	for i, e := range yes {
// 		if !IsServiceDisabled(e) {
// 			t.Errorf("yes[%d] not detected", i)
// 		}
// 	}
// 	no := []error{
// 		nil,
// 		errors.New("plain"),
// 		&googleapi.Error{Code: 403, Message: "Permission 'apikeys.keys.list' denied on resource"},
// 		&googleapi.Error{Code: 404, Message: "has not been used in project"},
// 		&googleapi.Error{Code: 429, Message: "SERVICE_DISABLED"},
// 	}
// 	for i, e := range no {
// 		if IsServiceDisabled(e) {
// 			t.Errorf("no[%d] wrongly detected", i)
// 		}
// 	}
// }

// TODO(GCP-7): Implement IsScopeInsufficient and enable this test
// func TestIsScopeInsufficient(t *testing.T) {
// 	yes := []error{
// 		&googleapi.Error{Code: 403, Message: "Provided scope(s) are not authorized"},
// 		fmt.Errorf("w: %w", &googleapi.Error{Code: 403, Message: "Request had insufficient authentication scopes."}),
// 		&googleapi.Error{Code: 403, Details: []interface{}{map[string]interface{}{"reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}}},
// 	}
// 	for i, e := range yes {
// 		if !IsScopeInsufficient(e) {
// 			t.Errorf("yes[%d] not detected", i)
// 		}
// 	}
// 	no := []error{
// 		nil,
// 		errors.New("Provided scope(s) are not authorized"), // not a googleapi error
// 		&googleapi.Error{Code: 403, Message: "Permission 'storage.hmacKeys.list' denied"},
// 		&googleapi.Error{Code: 401, Message: "Provided scope(s) are not authorized"},
// 	}
// 	for i, e := range no {
// 		if IsScopeInsufficient(e) {
// 			t.Errorf("no[%d] wrongly detected", i)
// 		}
// 	}
// }

// TODO(GCP-7): Implement IsAuthSecPool and enable this test
// func TestIsAuthSecPool(t *testing.T) {
// 	if !IsAuthSecPool("authsec-0123456789abcdef") {
// 		t.Error("derived pool shape not recognised")
// 	}
// 	for _, p := range []string{"", "authsec-", "authsec-XYZ", "authsec-0123456789abcdef0", "github-pool", "my-authsec-0123456789abcdef"} {
// 		if IsAuthSecPool(p) {
// 			t.Errorf("%q wrongly treated as AuthSec's pool", p)
// 		}
// 	}
// }
