package handlers

import (
	"fmt"

	repositories "github.com/authsec-ai/authsec/repository"
	sharedmodels "github.com/authsec-ai/sharedmodels"
	"github.com/google/uuid"
)

func mfaLookupIDs(user *sharedmodels.User) []string {
	if user == nil {
		return nil
	}

	ids := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	add := func(value uuid.UUID) {
		if value == uuid.Nil {
			return
		}
		key := value.String()
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		ids = append(ids, key)
	}

	add(user.ClientID)
	add(user.ID)
	return ids
}

func mfaPrimaryLookupID(user *sharedmodels.User) string {
	ids := mfaLookupIDs(user)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func mfaGetMethod(repo *repositories.MFARepository, user *sharedmodels.User, methodType string) (*sharedmodels.MFAMethod, string, error) {
	ids := mfaLookupIDs(user)
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("missing MFA lookup ids")
	}

	var lastErr error
	for _, id := range ids {
		method, err := repo.GetMethod(id, methodType)
		if err == nil {
			return method, id, nil
		}
		lastErr = err
	}

	return nil, "", lastErr
}

func mfaGetUserMethods(repo *repositories.MFARepository, user *sharedmodels.User) ([]sharedmodels.MFAMethod, string, error) {
	ids := mfaLookupIDs(user)
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("missing MFA lookup ids")
	}

	var lastErr error
	for _, id := range ids {
		methods, err := repo.GetUserMethods(id)
		if err == nil && len(methods) > 0 {
			return methods, id, nil
		}
		if err == nil {
			lastErr = nil
			continue
		}
		lastErr = err
	}

	return []sharedmodels.MFAMethod{}, ids[0], lastErr
}
