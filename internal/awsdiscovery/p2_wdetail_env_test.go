package awsdiscovery

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// wdetailLambda is a ListFunctions that returns these functions on one page.
type wdetailLambda struct {
	fns []lambdatypes.FunctionConfiguration
}

func (f wdetailLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return &lambda.ListFunctionsOutput{Functions: f.fns}, nil
}

// A function's environment is its variables when Lambda read them and an
// error when it could not (for example, KMS would not decrypt them). The
// second is NOT "no variables": the names are unknown, and the Workload says
// so (EnvVarsUnread) so that nothing downstream writes [] for it (D-85, the
// workload detail's provider_attrs.env_var_names). Names only, sorted; no
// value is ever copied.
func TestP2WdetailLambdaEnvironmentUnreadIsNotEmpty(t *testing.T) {
	fn := func(name string, env *lambdatypes.EnvironmentResponse) lambdatypes.FunctionConfiguration {
		return lambdatypes.FunctionConfiguration{FunctionArn: aws.String("arn:aws:lambda:us-east-1:111122223333:function:" + name),
			FunctionName: aws.String(name), Role: aws.String("arn:aws:iam::111122223333:role/r"), Environment: env}
	}
	r := NewWorkloadReader(wdetailLambda{fns: []lambdatypes.FunctionConfiguration{
		fn("with-vars", &lambdatypes.EnvironmentResponse{Variables: map[string]string{"B": "secret-b", "A": "secret-a"}}),
		fn("no-env", nil),
		fn("empty-env", &lambdatypes.EnvironmentResponse{Variables: map[string]string{}}),
		fn("kms-denied", &lambdatypes.EnvironmentResponse{Error: &lambdatypes.EnvironmentError{
			ErrorCode: aws.String("KMSAccessDeniedException"), Message: aws.String("Lambda was unable to decrypt the environment variables")}}),
	}}, nil, nil, nil)
	got, err := r.LambdaFunctions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Workload{}
	for _, w := range got {
		byName[w.Name] = w
		if strings.Contains(strings.Join(w.EnvVarNames, ","), "secret") {
			t.Fatalf("%s: a variable VALUE reached the workload: %v", w.Name, w.EnvVarNames)
		}
	}
	for name, want := range map[string]struct {
		names  string
		unread bool
	}{
		"with-vars":  {"A,B", false},
		"no-env":     {"", false},
		"empty-env":  {"", false},
		"kms-denied": {"", true},
	} {
		w, ok := byName[name]
		if !ok {
			t.Fatalf("%s was not listed", name)
		}
		if strings.Join(w.EnvVarNames, ",") != want.names || w.EnvVarsUnread != want.unread {
			t.Errorf("%s: names %v unread %v, want %q unread %v", name, w.EnvVarNames, w.EnvVarsUnread, want.names, want.unread)
		}
	}
}
