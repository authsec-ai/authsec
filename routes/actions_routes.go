package routes

import (
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/gin-gonic/gin"
)

// MountActions registers the v2 actions routes for collector-scoped action
// lists, forward catch-up changes, and per-action detail. The workload-scoped
// action list lives on the v1 graph catalogue (RegisterActionsOnGraphRoutes).
//
// All routes require iga:read and are behind AuthMiddleware. The workspace is
// taken from the token, never from a body or query parameter.
func MountActions(r gin.IRouter, ctl *platformCtrl.ActionsController) {
	if r == nil || ctl == nil {
		return
	}

	v2 := r.Group("/api/iga/v2")
	v2.Use(middlewares.AuthMiddleware())
	{
		// Collector-scoped action list — includes unattributed events.
		v2.GET("/collectors/:id/actions", middlewares.Require("iga", "read"), ctl.ListForCollector)

		// Per-action detail.
		v2.GET("/actions/:id", middlewares.Require("iga", "read"), ctl.GetAction)

		// Forward catch-up by activity_sequence.
		v2.GET("/actions/changes", middlewares.Require("iga", "read"), ctl.Changes)
	}
}
