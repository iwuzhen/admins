package admins

type AdminInfo struct {
	// 账号
	Account string `bson:"account,omitempty" json:"account"`

	// 手机号
	PhoneNumber string `bson:"phone_number,omitempty" json:"phone_number"`
}

type Admin struct {
	AdminInfo `bson:",inline"`
	// 密码
	Password string `bson:"password,omitempty" json:"password"`
}
