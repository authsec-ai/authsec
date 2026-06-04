package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock database for testing
type MockDB struct {
	mock.Mock
}

func (m *MockDB) Where(query interface{}, args ...interface{}) *MockDB {
	return m
}

func (m *MockDB) FirstOrCreate(value interface{}, conds ...interface{}) *MockDB {
	m.Called(value, conds)
	return m
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *MockDB {
	m.Called(dest, conds)
	return m
}

func (m *MockDB) Find(dest interface{}, conds ...interface{}) *MockDB {
	m.Called(dest, conds)
	return m
}

func (m *MockDB) Model(value interface{}) *MockDB {
	return m
}

func (m *MockDB) Association(column string) *MockAssociation {
	return &MockAssociation{}
}

func (m *MockDB) Delete(value interface{}, conds ...interface{}) *MockDB {
	m.Called(value, conds)
	return m
}

func (m *MockDB) Error() error {
	args := m.Called()
	return args.Error(0)
}

type MockAssociation struct {
	mock.Mock
}

func (m *MockAssociation) Append(values ...interface{}) error {
	args := m.Mock.Called(values)
	return args.Error(0)
}

func ensureControllerDB(t *testing.T) {
	if config.GetDatabase() != nil && config.DB != nil {
		return
	}
	// Force sane local defaults so InitDatabaseWithoutGORM connects
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "5432")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "postgres")
	if os.Getenv("DB_NAME") == "" {
		os.Setenv("DB_NAME", "authsec")
	}
	cfg := config.LoadConfig()
	config.InitDatabaseWithoutGORM(cfg)
	require.NotNil(t, config.GetDatabase(), "master DB should be initialized")
	require.NotNil(t, config.DB, "GORM DB should be initialized")
}

func skipIfNoSeed(t *testing.T) {
	t.Helper()
	if seededWorkspaceID == uuid.Nil {
		t.Skip("seed tenant not initialized (set RUN_INTEGRATION=1 to enable)")
	}
}

func TestGroupController_AddUserDefinedGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := &GroupController{}
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name           string
		input          models.UserDefinedGroupsRequest
		expectedStatus int
		expectedBody   map[string]interface{}
		setupMocks     func()
	}{
		{
			name: "successful group addition",
			input: models.UserDefinedGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{"Developers", "Administrators", "Users"},
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message": "Groups added successfully",
			},
			setupMocks: func() {},
		},
		{
			name:  "invalid request payload",
			input: models.UserDefinedGroupsRequest{
				// Missing required fields — controller binds to GroupRequest;
				// json.RawMessage with null passes required, so only WorkspaceID fails
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Invalid request payload: Key: 'GroupRequest.WorkspaceID' Error:Field validation for 'WorkspaceID' failed on the 'required' tag",
			},
			setupMocks: func() {},
		},
		{
			name: "empty groups list",
			input: models.UserDefinedGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "At least one group is required",
			},
			setupMocks: func() {},
		},
		{
			name: "database error",
			input: models.UserDefinedGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{"Developers"},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Failed to add groups: database connection not available",
			},
			setupMocks: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.name == "database error" {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			jsonData, _ := json.Marshal(tt.input)
			req, _ := http.NewRequest("POST", "/uflow/groups", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Request = req
			controller.AddUserDefinedGroups(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != nil {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				for key, expectedValue := range tt.expectedBody {
					assert.Equal(t, expectedValue, response[key])
				}
			}
		})
	}
}

func TestGroupController_MapGroupsToClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := &GroupController{}
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name           string
		input          models.MapGroupsRequest
		expectedStatus int
		checkError     bool // when true, only check status + error key contains "required"
		expectedBody   map[string]interface{}
		setupMocks     func()
	}{
		{
			name: "successful mapping",
			input: models.MapGroupsRequest{
				WorkspaceID: workspaceID,
				ClientID:    workspaceID,
				Groups:      []string{"Developers"},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"message": "Groups mapped to client successfully"},
			setupMocks:     func() {},
		},
		{
			name:           "missing required fields",
			input:          models.MapGroupsRequest{},
			expectedStatus: http.StatusBadRequest,
			checkError:     true, // binding error references MapGroupsRequest fields
			setupMocks:     func() {},
		},
		{
			name: "database error",
			input: models.MapGroupsRequest{
				WorkspaceID: workspaceID,
				ClientID:    workspaceID,
				Groups:      []string{"Developers"},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": "Failed to map groups to client: database connection not available"},
			setupMocks:     func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.name == "database error" {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			jsonData, _ := json.Marshal(tt.input)
			req, _ := http.NewRequest("POST", "/uflow/groups/map", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			c.Request = req
			controller.MapGroupsToClient(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.checkError {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				errMsg, ok := response["error"].(string)
				assert.True(t, ok, "response should contain error field")
				assert.True(t, strings.Contains(errMsg, "required"), "error should mention required validation")
			} else if tt.expectedBody != nil {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				for key, expectedValue := range tt.expectedBody {
					assert.Equal(t, expectedValue, response[key])
				}
			}
		})
	}
}

func TestGroupController_RemoveGroupsFromClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := &GroupController{}
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name           string
		input          models.RemoveGroupsRequest
		expectedStatus int
		checkError     bool
		expectedBody   map[string]interface{}
		setupMocks     func()
	}{
		{
			name: "successful removal",
			input: models.RemoveGroupsRequest{
				WorkspaceID: workspaceID,
				ClientID:    workspaceID,
				Groups:      []string{"Developers"},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"message": "Groups removed from client successfully"},
			setupMocks:     func() {},
		},
		{
			name:           "missing required fields",
			input:          models.RemoveGroupsRequest{},
			expectedStatus: http.StatusBadRequest,
			checkError:     true, // binding error references RemoveGroupsRequest fields
			setupMocks:     func() {},
		},
		{
			name: "database error",
			input: models.RemoveGroupsRequest{
				WorkspaceID: workspaceID,
				ClientID:    workspaceID,
				Groups:      []string{"Developers"},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": "Failed to remove groups from client: database connection not available"},
			setupMocks: func() {
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.name == "database error" {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			jsonData, _ := json.Marshal(tt.input)
			req, _ := http.NewRequest("DELETE", "/uflow/groups/remove", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			controller.RemoveGroupsFromClient(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.checkError {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				errMsg, ok := response["error"].(string)
				assert.True(t, ok, "response should contain error field")
				assert.True(t, strings.Contains(errMsg, "required"), "error should mention required validation")
			} else if tt.expectedBody != nil {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				for key, expectedValue := range tt.expectedBody {
					assert.Equal(t, expectedValue, response[key])
				}
			}
		})
	}
}

func TestGroupController_GetUserDefinedGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := &GroupController{}
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name           string
		workspaceID       string
		expectedStatus int
		expectedBody   map[string]interface{}
		setTenant      bool
		tamperDB       bool
	}{
		{
			name:           "successful retrieval",
			workspaceID:       workspaceID,
			expectedStatus: http.StatusOK,
			setTenant:      true,
		},
		{
			name:           "missing tenant ID",
			workspaceID:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   map[string]interface{}{"error": "Tenant ID not found in authentication token"},
			setTenant:      false,
		},
		{
			name:           "database error",
			workspaceID:       workspaceID,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": "Failed to fetch groups: database connection not available"},
			setTenant:      true,
			tamperDB:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			if tt.setTenant && tt.workspaceID != "" {
				c.Set("workspace_id", tt.workspaceID)
			}

			origDB := config.DB
			if tt.tamperDB {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			req := httptest.NewRequest("GET", "/uflow/groups/"+tt.workspaceID, nil)
			c.Request = req

			controller.GetUserDefinedGroups(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != nil {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				for key, expectedValue := range tt.expectedBody {
					assert.Equal(t, expectedValue, response[key])
				}
			}
		})
	}
}

func TestGroupController_DeleteUserDefinedGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := &GroupController{}
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name           string
		input          models.DeleteGroupsRequest
		expectedStatus int
		expectedBody   map[string]interface{}
		setTenant      bool
		tamperDB       bool
	}{
		{
			name: "successful group deletion",
			input: models.DeleteGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{uuid.New().String()},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"message": "Groups deleted successfully"},
			setTenant:      true,
		},
		{
			name: "successful group deletion - single group",
			input: models.DeleteGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{uuid.New().String()},
			},
			expectedStatus: http.StatusOK,
			expectedBody:   map[string]interface{}{"message": "Groups deleted successfully"},
			setTenant:      true,
		},
		{
			name: "missing tenant ID",
			input: models.DeleteGroupsRequest{
				Groups: []string{"GroupToDelete"},
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   map[string]interface{}{"error": "workspace_id not found in authentication token"},
			setTenant:      false,
		},
		{
			name: "empty groups list",
			input: models.DeleteGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   map[string]interface{}{"error": "At least one group-id is required"},
			setTenant:      true,
		},
		{
			name: "database error",
			input: models.DeleteGroupsRequest{
				WorkspaceID: workspaceID,
				Groups:      []string{"GroupToDelete"},
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   map[string]interface{}{"error": "Failed to delete groups: database connection not available"},
			setTenant:      true,
			tamperDB:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			if tt.setTenant && workspaceID != "" {
				c.Set("workspace_id", workspaceID)
			}

			if tt.input.WorkspaceID == "" && tt.setTenant && workspaceID != "" {
				tt.input.WorkspaceID = workspaceID
			}

			origDB := config.DB
			if tt.tamperDB {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			jsonData, _ := json.Marshal(tt.input)
			c.Request = httptest.NewRequest("DELETE", "/uflow/groups", bytes.NewBuffer(jsonData))
			c.Request.Header.Set("Content-Type", "application/json")

			controller.DeleteUserDefinedGroups(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != nil {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				for key, expectedValue := range tt.expectedBody {
					assert.Equal(t, expectedValue, response[key])
				}
			}
		})
	}
}

func TestAddUserDefinedGroups(t *testing.T) {
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name       string
		workspaceID   string
		groups     []string
		wantErr    bool
		setupMocks func()
	}{
		{
			name:     "successful group addition",
			workspaceID: workspaceID,
			groups:   []string{"Developers", "Administrators"},
			wantErr:  false,
			setupMocks: func() {
			},
		},
		{
			name:       "empty groups list",
			workspaceID:   workspaceID,
			groups:     []string{},
			wantErr:    false,
			setupMocks: func() {},
		},
		{
			name:     "database error",
			workspaceID: workspaceID,
			groups:   []string{"TestGroup"},
			wantErr:  true,
			setupMocks: func() {
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.name == "database error" {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			_, err := AddUserDefinedGroups(tt.workspaceID, tt.groups)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMapGroupsToClient(t *testing.T) {
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name       string
		workspaceID   string
		clientID   string
		groups     []string
		wantErr    bool
		setupMocks func()
	}{
		{
			name:     "successful mapping",
			workspaceID: workspaceID,
			clientID: workspaceID,
			groups:   []string{"Developers", "Administrators"},
			wantErr:  false,
			setupMocks: func() {
			},
		},
		{
			name:     "user not found",
			workspaceID: workspaceID,
			clientID: "non-existent-client",
			groups:   []string{"Developers"},
			wantErr:  true,
			setupMocks: func() {
			},
		},
		{
			name:     "groups not found",
			workspaceID: workspaceID,
			clientID: workspaceID,
			groups:   []string{"NonExistentGroup"},
			wantErr:  true,
			setupMocks: func() {
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			err := MapGroupsToClient(tt.workspaceID, tt.clientID, tt.groups)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetUserDefinedGroups(t *testing.T) {
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name       string
		workspaceID   string
		wantErr    bool
		tamperDB   bool
		setupMocks func()
	}{
		{
			name:       "successful retrieval",
			workspaceID:   workspaceID,
			wantErr:    false,
			setupMocks: func() {},
		},
		{
			name:       "database error",
			workspaceID:   workspaceID,
			wantErr:    true,
			tamperDB:   true,
			setupMocks: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.tamperDB {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			groups, err := GetUserDefinedGroups(tt.workspaceID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, groups)
			}
		})
	}
}

func TestDeleteUserDefinedGroups(t *testing.T) {
	ensureControllerDB(t)
	skipIfNoSeed(t)
	workspaceID := seededWorkspaceID.String()

	tests := []struct {
		name       string
		workspaceID   string
		groups     []string
		wantErr    bool
		tamperDB   bool
		setupMocks func()
	}{
		{
			name:     "successful deletion",
			workspaceID: workspaceID,
			groups:   []string{uuid.New().String(), uuid.New().String()},
			wantErr:  false,
			setupMocks: func() {
			},
		},
		{
			name:     "successful deletion - single group",
			workspaceID: workspaceID,
			groups:   []string{uuid.New().String()},
			wantErr:  false,
			setupMocks: func() {
			},
		},
		{
			name:       "empty groups list",
			workspaceID:   workspaceID,
			groups:     []string{},
			wantErr:    false,
			setupMocks: func() {},
		},
		{
			name:       "database error",
			workspaceID:   workspaceID,
			groups:     []string{"GroupToDelete"},
			wantErr:    true,
			tamperDB:   true,
			setupMocks: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			origDB := config.DB
			if tt.tamperDB {
				config.DB = nil
			}
			defer func() { config.DB = origDB }()

			err := DeleteUserDefinedGroups(tt.workspaceID, tt.groups)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
