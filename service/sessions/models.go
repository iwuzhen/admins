package sessions

import (
	"github.com/iwuzhen/admins/service/admins"
)

type Login struct {
	admins.AdminInfo `bson:",inline"`
	// 密码
	Password string `bson:"password" json:"password"`
}
