package app

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/externalsource"
	httpapi "github.com/simplexai-labs/linger/contracts-go/teamhubpublic"
)

// completeFeishuAuthorization exchanges the code a returning Feishu consent
// page carries. It runs without a session; the signed state authorizes it.
func (a *App) completeFeishuAuthorization(c *gin.Context) {
	var request httpapi.CompleteFeishuAuthorizationRequest
	if decodeJSON(c, &request) != nil {
		a.writeError(c, http.StatusBadRequest, "INVALID_REQUEST", "Feishu authorization request is invalid")
		return
	}
	err := a.externalSources.CompleteFeishuAuthorization(c.Request.Context(), request.State, request.Code)
	var missing *externalsource.FeishuScopesMissingError
	switch {
	case errors.As(err, &missing):
		code := "missing"
		details := make([]httpapi.ErrorDetail, 0, len(missing.Scopes))
		for _, scope := range missing.Scopes {
			details = append(details, httpapi.ErrorDetail{Field: "scope", Code: &code, Reason: scope})
		}
		a.writeErrorWithDetails(c, http.StatusBadRequest, "FEISHU_SCOPES_MISSING", "The Feishu app does not grant every mail permission yet", details)
	case errors.Is(err, externalsource.ErrFeishuNoRefreshToken):
		a.writeError(c, http.StatusBadRequest, "FEISHU_REFRESH_DISABLED", "The Feishu app does not issue refresh tokens")
	case errors.Is(err, externalsource.ErrFeishuAuthorizationRejected):
		a.writeError(c, http.StatusBadRequest, "FEISHU_AUTHORIZATION_REJECTED", "Feishu rejected this authorization; connect again")
	case errors.Is(err, externalsource.ErrInvalid):
		a.writeError(c, http.StatusBadRequest, "INVALID_REQUEST", "Feishu authorization request is invalid")
	case errors.Is(err, externalsource.ErrConflict):
		a.writeError(c, http.StatusConflict, "FEISHU_AUTHORIZATION_STALE", "This Feishu authorization is no longer current; connect again")
	case errors.Is(err, externalsource.ErrNotFound):
		a.writeError(c, http.StatusNotFound, "FEISHU_AUTHORIZATION_NOT_FOUND", "No connection waits for this Feishu authorization")
	case errors.Is(err, externalsource.ErrUnavailable):
		a.writeError(c, http.StatusServiceUnavailable, "EXTERNAL_SOURCE_UNAVAILABLE", "Feishu could not be reached; try again")
	case err != nil:
		a.internalError(c, "complete Feishu authorization", err)
	default:
		c.Status(http.StatusNoContent)
	}
}
