package admins

import (
	"errors"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/wzshiming/password"
)

type AdminWithID struct {
	ID         bson.ObjectId `bson:"_id,omitempty" json:"admin_id"`
	RoleID     bson.ObjectId `bson:"role_id,omitempty" json:"role_id"`
	CreateTime time.Time     `bson:"create_time,omitempty" json:"create_time"`
	Admin      `bson:",inline"`
}

// AdminsService #path:"/admins/"#
type AdminsService struct {
	name string
	db   *mgo.Collection
}

func NewAdminsService(name string, db *mgo.Collection) (*AdminsService, error) {
	err := db.EnsureIndex(mgo.Index{Key: []string{"account"}, Unique: true})
	if err != nil {
		return nil, err
	}
	return &AdminsService{name, db}, nil
}

// CreateNoauth
func (s *AdminsService) CreateNoauth(admin *AdminInfo) (adminID bson.ObjectId, err error) {
	count, _ := s.db.Find(bson.D{{"account", admin.Account}}).Count()
	if count != 0 {
		return "", errors.New("账号已经存在请勿重新注册")
	}
	adminID = bson.NewObjectId()
	err = s.db.Insert(AdminWithID{
		ID: adminID,
		Admin: Admin{
			AdminInfo: *admin,
		},
		CreateTime: bson.Now(),
	})
	if err != nil {
		return "", err
	}
	return adminID, nil
}

// Create #route:"POST /"#
func (s *AdminsService) Create(admin *Admin) (adminID bson.ObjectId, err error) {
	count, _ := s.db.Find(bson.D{{"account", admin.Account}}).Count()
	if count != 0 {
		return "", errors.New("账号已经存在请勿重新注册")
	}
	adminID = bson.NewObjectId()
	admin.Password = password.Encrypt(admin.Account + admin.Password)
	err = s.db.Insert(AdminWithID{
		ID:         adminID,
		Admin:      *admin,
		CreateTime: bson.Now(),
	})
	if err != nil {
		return "", err
	}
	return adminID, nil
}

// Verify #route:"POST /verify"#
func (s *AdminsService) Verify(admin *Admin) (adminWithID *AdminWithID, err error) {
	q := s.db.Find(bson.M{"account": admin.Account})
	err = q.One(&adminWithID)
	if err != nil || !password.Verify(adminWithID.Account+admin.Password, adminWithID.Password) {
		return nil, errors.New("用户名或密码错误")
	}
	adminWithID.Password = ""
	return adminWithID, nil
}

// Update #route:"PUT /{admin_id}"#
func (s *AdminsService) Update(adminID bson.ObjectId /*#name:"admin_id"#*/, admin *Admin) (err error) {
	admin.Password = password.Encrypt(admin.Account + admin.Password)
	return s.db.UpdateId(adminID, admin)
}

// UpdateRole #route:"PUT /{admin_id}/{role_id}"#
func (s *AdminsService) UpdateRole(adminID bson.ObjectId /*#name:"admin_id"#*/, roleID bson.ObjectId /*#name:"role_id"#*/) (err error) {
	return s.db.UpdateId(adminID, bson.D{{"$set", bson.D{{"role_id", roleID}}}})
}

// Delete #route:"DELETE /{admin_id}"#
func (s *AdminsService) Delete(adminID bson.ObjectId /*#name:"admin_id"#*/) (err error) {
	return s.db.RemoveId(adminID)
}

// Get #route:"GET /{admin_id}"#
func (s *AdminsService) Get(adminID bson.ObjectId /*#name:"admin_id"#*/) (adminWithID *AdminWithID, err error) {
	q := s.db.FindId(adminID) //.Select(bson.D{{"password", 0}})
	err = q.One(&adminWithID)
	if err != nil {
		return nil, err
	}
	return adminWithID, nil
}

// GetAccount 根据账号获取数据 #route:"GET /account/{account}"#
func (s *AdminsService) GetAccount(account string) (admin *AdminWithID, err error) {
	m := bson.D{}
	m = append(m, bson.DocElem{"account", account})

	q := s.db.Find(m)
	err = q.One(&admin)
	if err != nil {
		return nil, err
	}
	return admin, nil
}

// List 获取列表 #route:"GET /"#
func (s *AdminsService) List(filter string, startTime /* #name:"start_time"# */, endTime time.Time /* #name:"end_time"# */, offset, limit int) (admins []*AdminWithID, err error) {
	m := bson.D{}
	if filter != "" {
		m = append(m, bson.DocElem{"account", bson.RegEx{filter, "i"}})
	}
	if !startTime.IsZero() || !endTime.IsZero() {
		m0 := bson.D{}
		if !startTime.IsZero() {
			m0 = append(m0, bson.DocElem{"$gte", startTime})
		}
		if !endTime.IsZero() {
			m0 = append(m0, bson.DocElem{"$lt", endTime})
		}
		m = append(m, bson.DocElem{"create_time", m0})
	}
	q := s.db.Find(m).Skip(offset).Limit(limit) //.Select(bson.D{{"password", 0}})
	err = q.All(&admins)
	if err != nil {
		return nil, err
	}
	return admins, nil
}

// Count 获取数量 #route:"GET /count"#
func (s *AdminsService) Count(filter string, startTime /* #name:"start_time"# */, endTime time.Time /* #name:"end_time"# */) (count int, err error) {
	m := bson.D{}
	if filter != "" {
		m = append(m, bson.DocElem{"account", bson.RegEx{filter, "i"}})
	}
	if !startTime.IsZero() || !endTime.IsZero() {
		m0 := bson.D{}
		if !startTime.IsZero() {
			m0 = append(m0, bson.DocElem{"$gte", startTime})
		}
		if !endTime.IsZero() {
			m0 = append(m0, bson.DocElem{"$lt", endTime})
		}
		m = append(m, bson.DocElem{"create_time", m0})
	}
	q := s.db.Find(m)
	return q.Count()
}
