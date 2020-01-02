package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/prometheus/common/log"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io/ioutil"
	"net/http"
	"time"
)

var googleOauthConfig *oauth2.Config
var store = sessions.NewCookieStore([]byte("33446a9dcf9ea060a0a6532b166da32f304af0de"))
const SessionKey = "sessionid"

func Initialize(v *viper.Viper) {
	googleOauthConfig = &oauth2.Config{
		ClientID:     v.GetString("auth.google.client-id"),
		ClientSecret: v.GetString("auth.google.client-secret"),
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://me.olee.com:8080/callback",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
	}
	log.Infof("googole oauth config %v",googleOauthConfig)
	port := v.GetString("http.port")

	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleGoogleLogin)
	http.HandleFunc("/callback",handleGoogleCallback)
	http.HandleFunc("/secure", loggedIn(secureHandler))
	http.HandleFunc("/logout", loggedIn(logoutHandler))

	http.HandleFunc("/api/login", handleApiGoogleLogin)
	http.HandleFunc("/api/callback", handleApiGoogleCallback)

	log.Fatal(http.ListenAndServe(":"+port, nil))
}


func main() {
	v := viper.New()
	v.SetConfigName("config.yml")
	v.AddConfigPath("config/")
	err := v.ReadInConfig()

	if err != nil {
		log.Errorf("cannot read viper config, %v", err)
	}
	log.Infof("viper keys: %v",v.AllKeys())

	Initialize(v)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r,SessionKey)
	session.Values["login"] = false
	session.Options.MaxAge = -1
	session.Save(r,w)
	http.Redirect(w,r,"/", http.StatusFound)
}

func loggedIn(fn http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		session,_ := store.Get(r,SessionKey)
		if session.Values["login"] == true {
			fn(w,r)
		}else {
			http.Redirect(w,r,"/",http.StatusTemporaryRedirect)
		}
	}
}




type UserView struct {
	Email string
	Name string
	Picture string
}
func secureHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r,SessionKey)
	log.Infof("session %v\n", session)
	user := UserView{
		Email:  session.Values["email"].(string),
		Name:   session.Values["name"].(string),
		Picture: session.Values["picture"].(string),
	}


	secureTmlp := template.Must(template.ParseFiles("templates/logout.html"))


	secureTmlp.Execute(w, &user)

	w.Write([]byte(fmt.Sprintf("%v", session.Values)))
}

type StateOauth struct {
	Caller string
	CallerRedirect string
	Rand []byte
}
func generateStateOauthCookie(w http.ResponseWriter, r *http.Request) []byte {
	var exp = time.Now().Add(24* time.Hour)
	state := &StateOauth{
		Caller:         r.Host,
		CallerRedirect: "",
		Rand:           make([]byte,16),
	}
	rand.Read(state.Rand)
	buff, _ := json.Marshal(&state)
	stateEnc := base64.URLEncoding.EncodeToString(buff)
	cookie := http.Cookie{Name:"oauthstate",Value:stateEnc, Expires:exp}
	http.SetCookie(w, &cookie)
	return []byte(stateEnc)
}


func handleMain(w http.ResponseWriter, r *http.Request) {

	homeTmlp := template.Must(template.ParseFiles("templates/home.html"))
	homeTmlp.Execute(w,nil)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	oauthStateBuff := generateStateOauthCookie(w,r)
	url := googleOauthConfig.AuthCodeURL(string(oauthStateBuff))
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		log.Errorf("cannot find oauthstate cookie, %v",err.Error())
		http.Redirect(w,r,"/", http.StatusTemporaryRedirect)
		return
	}
	log.Infof("state from request form [%v]",r.FormValue("state"))
	log.Infof("state from cookie [%v]",oauthState.Value)
	if r.FormValue("state") != oauthState.Value {
		log.Errorf("oauth state mismatch")
		http.Redirect(w,r,"/", http.StatusTemporaryRedirect)
		return
	}
	buff, err := getUserDataFromGoogle(r.FormValue("code"))
	if err != nil {
		log.Errorf("cannot get user data from google using code, %v", err)
		http.Redirect(w,r,"/", http.StatusTemporaryRedirect)
		return
	}
	log.Infof("response from google oauth %v\n", string(buff))
	var data map[string]interface{}
	err = json.Unmarshal(buff, &data)
	if err != nil {
		log.Errorf("cannot unmarshal data from google %v", err)
		http.Redirect(w,r,"/", http.StatusTemporaryRedirect)
		return
	}

	email,_ := data["email"].(string)
	name,_ := data["name"].(string)
	picture,_ := data["picture"].(string)
	id,_ := data["id"].(string)
	session, _ := store.Get(r, SessionKey)
	session.Options = &sessions.Options{
		Path:     "/",
		Domain:   "me.olee.com",
		MaxAge:   24*3600,
	}
	session.Values["email"] = email
	session.Values["name"] = name
	session.Values["login"] = len(email) > 0 || len(name) > 0
	session.Values["picture"] = picture
	session.Values["id"] = id
	session.Save(r,w)
	log.Infof("session info: %v", session.Values)
	http.Redirect(w,r,"/secure", http.StatusFound)
}

func getUserDataFromGoogle(code string) ([]byte, error) {
	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange error", err.Error())
	}
	response, err := http.Get("https://www.googleapis.com/userinfo/v2/me?alt=json&access_token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	content, err := ioutil.ReadAll(response.Body)
	log.Infof("api response: %v",string(content))
	return content, err
}

func handleApiGoogleLogin(w http.ResponseWriter, r *http.Request) {

}

func handleApiGoogleCallback(w http.ResponseWriter, r *http.Request) {

}
