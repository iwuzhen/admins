package admin

import (
	"net/http"

	"gitlab.com/genned/admins/service/admins"
	"gitlab.com/genned/admins/service/sessions"
)

// Admin #middleware:"admin"#
func Admin(r *http.Request) (admin *admins.AdminWithID, err error) {
	ctx := r.Context()
	adminI := ctx.Value(sessions.KeyAdmin)
	admin, _ = adminI.(*admins.AdminWithID)

	return admin, nil
}
