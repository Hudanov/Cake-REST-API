package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type Params = map[string]interface{}

func TestAdmin(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("promote user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		adms := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.promoteUser)))
		defer func() {
			adms.Close()
		}()

		user := newUser()
		userJwt, _ := j.GenearateJWT(user)
		u.repository.Add(user.Email, user)

		superadmin := newSuperadmin()
		superadminJwt, _ := j.GenearateJWT(superadmin)
		u.repository.Add(superadmin.Email, superadmin)

		promoteParams := Params{
			"email": user.Email,
		}

		req, err := http.NewRequest(http.MethodGet, adms.URL, prepareParams(t, promoteParams)) // make user admin
		req.Header.Add(
			"Authorization",
			"Bearer "+superadminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, "user "+user.Email+" is admin now", resp)

		if usr, _ := u.repository.Get(user.Email); usr.Role != adminRole {
			t.Errorf("'"+usr.Email+" expected to be admin, but it was %s", usr.Role)
		}

		req, err = http.NewRequest(http.MethodGet, adms.URL, prepareParams(t, promoteParams)) // make user admin
		req.Header.Add(
			"Authorization",
			"Bearer "+userJwt,
		)

		usr, _ := u.repository.Delete(user.Email)
		usr.Role = userRole
		u.repository.Add(usr.Email, usr)

		resp = doRequest(req, err)

		assertResponse(t, 401, "try to acces superadmin api without superadmin rights", resp)

		if usr, _ := u.repository.Get(user.Email); usr.Role == adminRole {
			t.Errorf("'"+user.Email+" expected to be not admin, but it was %s", usr.Role)
		}
	})

	t.Run("fire user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		adms := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.fireUser)))
		defer func() {
			adms.Close()
		}()

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		superadmin := newSuperadmin()
		superadminJwt, _ := j.GenearateJWT(superadmin)
		u.repository.Add(superadmin.Email, superadmin)

		fireParams := Params{
			"email": admin.Email,
		}

		req, err := http.NewRequest(http.MethodGet, adms.URL, prepareParams(t, fireParams)) // make admin user
		req.Header.Add(
			"Authorization",
			"Bearer "+superadminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, "user "+admin.Email+" is not admin now", resp)

		if usr, _ := u.repository.Get(admin.Email); usr.Role == adminRole {
			t.Errorf("'test@mail.com' expected to be not admin, but it was %s", usr.Role)
		}

		req, err = http.NewRequest(http.MethodGet, adms.URL, prepareParams(t, Params{
			"email": superadmin.Email,
		})) // try to make superadmin not admin
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp = doRequest(req, err)

		assertResponse(t, 401, "try to acces superadmin api without superadmin rights", resp)
	})

	t.Run("banned user tries to acces api", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		jwts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		cks := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, getCakeHandler)))
		defer func() {
			jwts.Close()
			cks.Close()
		}()

		user := newUser()
		userJwt, _ := j.GenearateJWT(user)

		user.BanHistory = &[]Ban{}
		u.repository.Add(user.Email, user)
		u.BanUser(user.Email, "admin@mail.com", "test")

		resp := doRequest(http.NewRequest(http.MethodPost, jwts.URL, prepareParams(t, Params{ // user tries to acces user api
			"email":    user.Email,
			"password": DefaultPassword,
		})))

		assertResponse(t, 401, "user "+user.Email+" has ban due to 'test'", resp)

		req, err := http.NewRequest(http.MethodPost, cks.URL, nil) // get cake
		req.Header.Add(
			"Authorization",
			"Bearer "+userJwt,
		)

		resp = doRequest(req, err)

		assertResponse(t, 401, "user "+user.Email+" has ban due to 'test'", resp)
	})

	t.Run("unbanned user tries to acces api", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		jwts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		cks := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, getCakeHandler)))
		defer func() {
			jwts.Close()
			cks.Close()
		}()

		user := newUser()
		userJwt, _ := j.GenearateJWT(user)

		user.BanHistory = &[]Ban{}
		u.repository.Add(user.Email, user)
		u.BanUser(user.Email, "admin@mail.com", "test")
		u.UnbanUser(user.Email, "admin@mail.com")

		resp := doRequest(http.NewRequest(http.MethodPost, jwts.URL, prepareParams(t, Params{ // user tries to acces user api
			"email":    user.Email,
			"password": DefaultPassword,
		})))

		assertResponse(t, 200, userJwt, resp)

		req, err := http.NewRequest(http.MethodPost, cks.URL, nil) // get cake
		req.Header.Add(
			"Authorization",
			"Bearer "+userJwt,
		)

		resp = doRequest(req, err)

		assertResponse(t, 200, "cheesecake", resp)
	})

	t.Run("ban user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		bans := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.banUserHandler)))
		defer func() {
			bans.Close()
		}()

		user := newUser()
		// userJwt, _ := j.GenearateJWT(user)
		u.repository.Add(user.Email, user)

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		superadmin := newSuperadmin()
		// superadminJwt, _ := j.GenearateJWT(superadmin)
		u.repository.Add(superadmin.Email, superadmin)

		banParams := Params{
			"email":  user.Email,
			"reason": "test",
		}

		req, err := http.NewRequest(http.MethodPost, bans.URL, prepareParams(t, banParams)) // ban user
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, "user "+user.Email+" is banned now", resp)

		resp = doRequest(req, err) // try to ban user again

		assertResponse(t, 422, "user "+user.Email+" is already banned", resp)

		banParams = Params{
			"email":  superadmin.Email,
			"reason": "test",
		}

		req, err = http.NewRequest(http.MethodPost, bans.URL, prepareParams(t, banParams)) // try to ban superadmin
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp = doRequest(req, err)

		assertResponse(t, 401, "not enough rights to performe this action", resp)
	})

	t.Run("unban user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		unbans := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.unbanUserHandler)))
		defer func() {
			unbans.Close()
		}()

		user := newUser()
		// userJwt, _ := j.GenearateJWT(user)

		user.BanHistory = &[]Ban{}
		u.repository.Add(user.Email, user)
		u.BanUser(user.Email, "admin@mail.com", "test")

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		unbanParams := Params{
			"email": user.Email,
		}

		req, err := http.NewRequest(http.MethodPost, unbans.URL, prepareParams(t, unbanParams)) // unban user
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, "user "+user.Email+" is unbanned now", resp)

		resp = doRequest(req, err) // try to unban user again

		assertResponse(t, 422, "user "+user.Email+" does not have any active bans", resp)
	})

	t.Run("inspect user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		inspects := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.inspectUserHandler)))
		defer func() {
			inspects.Close()
		}()

		user := newUser()
		// userJwt, _ := j.GenearateJWT(user)

		user.BanHistory = &[]Ban{}
		u.repository.Add(user.Email, user)
		u.BanUser(user.Email, "admin@mail.com", "test")
		u.UnbanUser(user.Email, "anotheradmin@mail.com")

		u.BanUser(user.Email, "admin@mail.com", "another test")

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		req, err := http.NewRequest(http.MethodPost, inspects.URL+"?email="+user.Email, nil) // inspect
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, InspectUser(user), resp)
	})

	t.Run("inspect clear user", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		inspects := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.inspectUserHandler)))
		defer func() {
			inspects.Close()
		}()

		user := newUser()
		u.repository.Add(user.Email, user)

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		req, err := http.NewRequest(http.MethodPost, inspects.URL+"?email="+user.Email, nil) // inspect
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, http.StatusOK, "user "+user.Email+" does not have any bans", resp)
	})

	t.Run("inspect without email", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		inspects := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.inspectUserHandler)))
		defer func() {
			inspects.Close()
		}()

		user := newUser()
		u.repository.Add(user.Email, user)

		admin := newAdmin()
		adminJwt, _ := j.GenearateJWT(admin)
		u.repository.Add(admin.Email, admin)

		req, err := http.NewRequest(http.MethodPost, inspects.URL, nil) // inspect
		req.Header.Add(
			"Authorization",
			"Bearer "+adminJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, 422, "Unvalid email address", resp)
	})

	t.Run("users can not acces admin api", func(t *testing.T) {
		u := newTestUserService()
		j := newTestJwtService(t)

		bans := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.banUserHandler)))
		adms := httptest.NewServer(http.HandlerFunc(j.JWTAuth(u.repository, u.promoteUser)))
		defer func() {
			bans.Close()
		}()

		user := newUser()
		userJwt, _ := j.GenearateJWT(user)
		u.repository.Add(user.Email, user)

		testUser := newUser()
		u.repository.Add(testUser.Email, testUser)

		banParams := Params{
			"email":  testUser.Email,
			"reason": "test",
		}

		req, err := http.NewRequest(http.MethodPost, bans.URL, prepareParams(t, banParams)) // ban user
		req.Header.Add(
			"Authorization",
			"Bearer "+userJwt,
		)

		resp := doRequest(req, err)

		assertResponse(t, 401, "not enough rights to performe this action", resp)

		promoteParams := Params{
			"email": testUser.Email,
		}

		req, err = http.NewRequest(http.MethodPost, adms.URL, prepareParams(t, promoteParams)) // ban user
		req.Header.Add(
			"Authorization",
			"Bearer "+userJwt,
		)

		resp = doRequest(req, err)

		assertResponse(t, 401, "try to acces superadmin api without superadmin rights", resp)

	})

	t.Run("add superadmin test", func(t *testing.T) {

		u := newTestUserService()

		assertEmail := "Undefined superadmin email"
		assertPassword := "Undefined superadmin password"
		email := "superadmin@openware.com"
		password := "12345678"

		err := u.addSuperadmin()
		if err.Error() != assertEmail {
			t.Errorf("Expected %s but get %s", assertEmail, err.Error())
		}

		os.Setenv("CAKE_ADMIN_EMAIL", email)
		err = u.addSuperadmin()
		if err.Error() != assertPassword {
			t.Errorf("Expected %s but get %s", assertEmail, err.Error())
		}

		os.Setenv("CAKE_ADMIN_PASSWORD", password)
		err = u.addSuperadmin()
		if err != nil {
			t.Errorf(err.Error())
		}

		_, err = u.repository.Get(email)
		if err != nil {
			t.Errorf(err.Error())
		}

	})
}
