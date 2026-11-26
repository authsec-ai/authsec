package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/dto"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// requestWorkspace returns the request's workspace, which an authentication
// middleware resolved from a verified credential (platform token or client
// certificate). Never from the body, query or a header.
func requestWorkspace(c *gin.Context) (string, error) {
	ws, err := tenancy.Workspace(c)
	if err != nil {
		return "", errors.NewUnauthorizedError("No workspace resolved for this request", err)
	}
	return ws.String(), nil
}

// sameWorkspace refuses, as not found, a request that names a workspace
// other than the authenticated one. An empty value is fine.
func sameWorkspace(c *gin.Context, asserted string) error {
	if asserted == "" {
		return nil
	}
	ws, err := requestWorkspace(c)
	if err != nil {
		return err
	}
	if asserted != ws {
		return errors.NewNotFoundError("Not found", nil)
	}
	return nil
}

// sendError writes err as the module's error envelope.
func sendError(c *gin.Context, logger *logrus.Entry, err error) {
	appErr, ok := err.(*errors.AppError)
	if !ok {
		appErr = errors.NewInternalError("Internal server error", err)
	}
	logger.WithFields(logrus.Fields{"code": appErr.Code, "message": appErr.Message}).
		WithError(appErr.Err).Warn("SPIRE request failed")
	c.JSON(appErr.Status, dto.ErrorResponse{Error: dto.ErrorDetail{Code: appErr.Code, Message: appErr.Message}})
}
