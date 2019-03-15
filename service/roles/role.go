// Code generated; Do not regenerate the overwrite after editing.

package roles

import (
	"strings"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/gorilla/mux"
)

// RoleWithID is Role with ID
type RoleWithID struct {
	ID         bson.ObjectId `bson:"_id,omitempty" json:"role_id"`
	Role       `bson:",inline"`
	CreateTime time.Time `bson:"create_time,omitempty" json:"create_time"`
	UpdateTime time.Time `bson:"update_time,omitempty" json:"update_time"`
}

type RoleRecord struct {
	ID          bson.ObjectId `bson:"_id,omitempty" json:"role_record_id"`
	RoleID      bson.ObjectId `bson:"role_id,omitempty" json:"role_id"`
	Recent      *Role         `bson:"recent,omitempty" json:"recent"`
	Current     *Role         `bson:"current,omitempty" json:"current"`
	RecentTime  time.Time     `bson:"recent_time,omitempty" json:"recent_time"`
	CurrentTime time.Time     `bson:"current_time,omitempty" json:"current_time"`
	Times       int           `bson:"times,omitempty" json:"times"`
}

// RoleService #path:"/role/"#
type RoleService struct {
	db       *mgo.Collection
	dbRecord *mgo.Collection
	auth     map[string]map[string]bool
}

// NewRoleService Create a new RoleService
func NewRoleService(db *mgo.Collection) (*RoleService, error) {
	dbRecord := db.Database.C(db.Name + "_record")
	dbRecord.EnsureIndex(mgo.Index{Key: []string{"role_id"}})
	return &RoleService{
		db:       db,
		dbRecord: dbRecord,
		auth:     map[string]map[string]bool{},
	}, nil
}

func (s *RoleService) LoadAuths(router *mux.Router) error {
	return router.Walk(s.loadAuths)
}

func (s *RoleService) loadAuths(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
	methods, err := route.GetMethods()
	if err != nil {
		return nil
	}
	path, err := route.GetPathTemplate()
	if err != nil {
		return err
	}

	for _, method := range methods {
		if s.auth[path] == nil {
			s.auth[path] = map[string]bool{}
		}
		s.auth[path][method] = false
	}

	return nil
}

// GetAuth 获取的用户的权限  #route:"GET /auth"#
func (s *RoleService) GetAuth() (allow map[string]map[string]bool, err error) {
	return s.auth, nil
}

// GetAuthBy 获取的用户的权限  #route:"GET /auth/{role_id}"#
func (s *RoleService) GetAuthBy(roleID bson.ObjectId /* #name:"role_id"# */) (allow map[string]map[string]bool, err error) {
	if roleID == "" {
		return s.auth, nil
	}
	q := s.db.FindId(roleID)
	err = q.One(&allow)
	if err != nil {
		return nil, err
	}
	return allow, nil
}

// Update the Role #route:"PUT /auth/{role_id}"#
func (s *RoleService) UpdateAuth(roleID bson.ObjectId /* #name:"role_id"# */, auth *Auth) (err error) {
	m := bson.D{{strings.Join([]string{"allow", auth.Path, auth.Method}, "."), auth.Allow}}
	err = s.db.UpdateId(roleID, m)
	if err != nil {
		return err
	}
	return nil
}

// Check 检查角色是否有调用权限
func (s *RoleService) Check(roleID bson.ObjectId /* #name:"role_id"# */, method, path string) bool {
	r, err := s.Get(roleID)
	if err != nil {
		return false
	}
	allow := r.Allow
	if r.Auth == nil {
		return allow
	}
	a1, ok := r.Auth[path]
	if !ok {
		return allow
	}
	a2, ok := a1[method]
	if !ok {
		return allow
	}
	return a2
}

// Create a Role #route:"POST /"#
func (s *RoleService) Create(role *Role) (roleID bson.ObjectId /* #name:"role_id"# */, err error) {
	roleID = bson.NewObjectId()
	now := bson.Now()
	err = s.db.Insert(&RoleWithID{
		ID:         roleID,
		Role:       *role,
		CreateTime: now,
		UpdateTime: now,
	})
	if err != nil {
		return "", err
	}
	return roleID, nil
}

// Update the Role #route:"PUT /{role_id}"#
func (s *RoleService) Update(roleID bson.ObjectId /* #name:"role_id"# */, role *Role) (err error) {
	recent, err := s.Get(roleID)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil
		}
		return err
	}

	err = s.db.UpdateId(roleID, bson.D{{"$set", &RoleWithID{
		Role:       *role,
		UpdateTime: bson.Now(),
	}}})
	if err != nil {
		return err
	}

	current, err := s.Get(roleID)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil
		}
		return err
	}

	err = s.record(recent, &current.Role)
	if err != nil {
		return err
	}

	return nil
}

// Delete the Role #route:"DELETE /{role_id}"#
func (s *RoleService) Delete(roleID bson.ObjectId /* #name:"role_id"# */) (err error) {
	recent, err := s.Get(roleID)
	if err != nil {
		if err == mgo.ErrNotFound {
			return nil
		}
		return err
	}

	err = s.db.RemoveId(roleID)
	if err != nil {
		return err
	}

	err = s.record(recent, nil)
	if err != nil {
		return err
	}

	return nil
}

// Get the Role #route:"GET /{role_id}"#
func (s *RoleService) Get(roleID bson.ObjectId /* #name:"role_id"# */) (role *RoleWithID, err error) {
	q := s.db.FindId(roleID)
	err = q.One(&role)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// List of the Role #route:"GET /"#
func (s *RoleService) List(startTime /* #name:"start_time"# */, endTime time.Time /* #name:"end_time"# */, offset, limit int) (roles []*RoleWithID, err error) {
	m := bson.D{}
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
	q := s.db.Find(m).Skip(offset).Limit(limit)
	err = q.All(&roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// Count of the Role #route:"GET /count"#
func (s *RoleService) Count(startTime /* #name:"start_time"# */, endTime time.Time /* #name:"end_time"# */) (count int, err error) {
	m := bson.D{}
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

// RecordList of the Role record list #route:"GET /{role_id}/record"#
func (s *RoleService) RecordList(roleID bson.ObjectId /* #name:"role_id"# */, offset, limit int) (roleRecords []*RoleRecord, err error) {
	m := bson.D{{"role_id", roleID}}
	q := s.dbRecord.Find(m).Skip(offset).Limit(limit)
	err = q.All(&roleRecords)
	if err != nil {
		return nil, err
	}
	return roleRecords, nil
}

// RecordCount of the Role record count #route:"GET /{role_id}/record/count"#
func (s *RoleService) RecordCount(roleID bson.ObjectId /* #name:"role_id"# */) (count int, err error) {
	m := bson.D{{"role_id", roleID}}
	q := s.dbRecord.Find(m)
	return q.Count()
}

func (s *RoleService) record(role *RoleWithID, current *Role) error {
	if role == nil {
		return nil
	}
	count, err := s.dbRecord.Find(bson.D{{"role_id", role.ID}}).Count()
	if err != nil {
		return err
	}
	record := &RoleRecord{
		RoleID:      role.ID,
		Current:     current,
		CurrentTime: bson.Now(),
		Times:       count + 1,
		Recent:      &role.Role,
		RecentTime:  role.UpdateTime,
	}
	return s.dbRecord.Insert(record)
}
