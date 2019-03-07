package sessions

import (
	"gitlab.com/genned/admins/service/admins"
)

type Login struct {
	admins.AdminInfo `bson:",inline"`
	// 密码
	Password string `bson:"password" json:"password"`
}
