package admin

import (
	"net/http"

	"github.com/iwuzhen/admins/service/admins"
	"github.com/iwuzhen/admins/service/sessions"
)

// Admin #middleware:"admin"#
func Admin(r *http.Request) (admin *admins.AdminWithID, err error) {
	ctx := r.Context()
	adminI := ctx.Value(sessions.KeyAdmin)
	admin, _ = adminI.(*admins.AdminWithID)

	return admin, nil
}
