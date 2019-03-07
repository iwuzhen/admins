package roles

// Role 角色
type Role struct {
	// 名字
	Name string `bson:"name,omitempty" json:"name"`
	// 默认是否允许
	Allow bool `bson:"allow,omitempty" json:"allow"`
	// map[path][method]allow
	Auth map[string]map[string]bool `bson:"auth,omitempty" json:"auth"`
}

// Auth 权限
type Auth struct {
	// 方法
	Method string `bson:"method" json:"method"`
	// 路径
	Path string `bson:"path" json:"path"`
	// 是否允许
	Allow bool `bson:"allow" json:"allow"`
}
