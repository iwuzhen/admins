package sessions

import (
	"context"
	"encoding/gob"
	"errors"
	"net/http"

	"github.com/globalsign/mgo"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/kidstuff/mongostore"
	"gitlab.com/genned/admins/service/admins"
	"gitlab.com/genned/roles/service/roles"
)

func init() {
	gob.Register(&admins.AdminWithID{})
}

// SessionsService #path:"/sessions/"#
type SessionsService struct {
	name   string
	store  *mongostore.MongoStore
	admins *admins.AdminsService
	role   *roles.RoleService
}

func NewSessionsService(name string, db *mgo.Collection, admins *admins.AdminsService, role *roles.RoleService) (*SessionsService, error) {
	store := mongostore.NewMongoStore(db, 0, true, []byte("genned/admins"))
	return &SessionsService{name, store, admins, role}, nil
}

const KeyAdmin = `x-admin`

func (s *SessionsService) VerifyNoauth(handler http.Handler) http.Handler {
	return s.verify(handler, true)
}

func (s *SessionsService) Verify(handler http.Handler) http.Handler {
	return s.verify(handler, false)
}

func (s *SessionsService) verify(handler http.Handler, noauth bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		session, err := s.store.Get(r, s.name)
		if err != nil {
			if noauth {
				handler.ServeHTTP(w, r)
				return
			}

			http.Error(w, "请先登入", 403)
			return
		}
		admin, ok := session.Values[KeyAdmin]
		if !ok {
			if noauth {
				handler.ServeHTTP(w, r)
				return
			}

			http.Error(w, "请先登入", 403)
			return
		}
		if s.role != nil {
			cr := mux.CurrentRoute(r)
			method := r.Method
			path, err := cr.GetPathTemplate()
			if err != nil {
				http.Error(w, err.Error(), 401)
				return
			}

			adminI, _ := admin.(*admins.AdminWithID)
			adminI, err = s.admins.Get(adminI.ID)
			if err != nil {
				s.Logout(w, r)
				http.Error(w, "登入信息已过期", 403)
				return
			}

			if adminI.RoleID == "" {
				http.Error(w, "没有任何权限", 401)
				return
			}

			if !s.role.Check(adminI.RoleID, method, path) {
				http.Error(w, "没有调用该接口权限", 401)
				return
			}
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, KeyAdmin, admin)
		r = r.WithContext(ctx)

		handler.ServeHTTP(w, r)
	})
}

func (s *SessionsService) LoginNoauth(login *admins.AdminInfo, create bool, w http.ResponseWriter, r *http.Request) (admin *admins.AdminWithID, err error) {
	admin, err = s.admins.GetAccount(login.Account)

	if err != nil {
		if !create {
			return nil, errors.New("该用户不存在")
		}

		// 不存在 则创建用户的
		adminID, err := s.admins.CreateNoauth(login)
		if err != nil {
			return nil, err
		}

		admin, err = s.admins.Get(adminID)
		if err != nil {
			return nil, err
		}
	}

	session, err := s.store.Get(r, s.name)
	if err != nil {
		return nil, err
	}
	admin.Password = ""
	session.Values[KeyAdmin] = admin
	err = s.store.Save(r, w, session)
	if err != nil {
		return nil, err
	}
	return admin, nil
}

// Login #route:"POST /login"#
func (s *SessionsService) Login(login *Login, w http.ResponseWriter, r *http.Request) (admin *admins.AdminWithID, err error) {
	admin, err = s.admins.Verify(&admins.Admin{
		AdminInfo: login.AdminInfo,
		Password:  login.Password,
	})
	if err != nil {
		return nil, err
	}

	session, err := s.store.Get(r, s.name)
	if err != nil {
		return nil, err
	}
	admin.Password = ""
	session.Values[KeyAdmin] = admin
	err = s.store.Save(r, w, session)
	if err != nil {
		return nil, err
	}
	return admin, nil
}

// Logout #route:"POST /logout"#
func (s *SessionsService) Logout(w http.ResponseWriter, r *http.Request) (err error) {
	session, err := s.store.Get(r, s.name)
	if err != nil {
		return nil
	}

	session.Values = map[interface{}]interface{}{}
	err = s.store.Save(r, w, session)
	if err != nil {
		return err
	}
	return nil
}

// Check #route:"POST /check"#
func (s *SessionsService) Check(r *http.Request) (admin *admins.AdminWithID, err error) {
	session, err := s.store.Get(r, s.name)
	if err != nil {
		return nil, err
	}

	adminI, ok := session.Values[KeyAdmin]
	if !ok {
		return nil, nil
	}

	admin, _ = adminI.(*admins.AdminWithID)
	return admin, nil
}

func (s *SessionsService) GetSession(r *http.Request) (*sessions.Session, error) {
	return s.store.Get(r, s.name)

}

func (s *SessionsService) SaveSession(w http.ResponseWriter, r *http.Request, session *sessions.Session) error {
	return s.store.Save(r, w, session)

}
