package main

import (
	"code.google.com/p/go.text/encoding/simplifiedchinese"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	// "os/exec"
	// "strconv"
	"strings"

	"./tools"
)

type Config struct {
	Nonce    string
	Cnonce   string
	Username string
	Password string
}

type Item struct {
	User string
	IP   string
	Mac  string
	Auth bool
}

type Storage struct {
	Base   int
	Prefix string

	Items []Item
}

func (s *Storage) Save() {
	data, err := json.Marshal(s)
	if err != nil {
		log.Println("Marshal Failed:", err)
		return
	}
	err = ioutil.WriteFile("data/bind.json", data, 0655)
	if err != nil {
		log.Println("Write Failed:", err)
		return
	}
}
func (s *Storage) Load() {
	data, err := ioutil.ReadFile("data/bind.json")
	if err != nil {
		log.Println("Load Failed:", err)
		return
	}

	err = json.Unmarshal(data, s)
	if err != nil {
		log.Println("Unmarshal:", err)
		return
	}
}

var g_Storage Storage
var g_Config Config

func RegPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("template/reg.html")
	tmpl.Execute(w, nil)
}

type OpRouter struct {
	nc     int
	cnonce string
}

var g_OpRouter OpRouter

func (op *OpRouter) GetValue(key string, auth string) string {
	offset := strings.Index(auth, key)
	if offset == -1 {
		log.Println("index:", key, auth)
		return ""
	}
	value := auth[offset+len(key)+1:]
	if value[0] == '"' {
		value = value[1:]
		value = value[:strings.Index(value, "\"")]
	} else {
		log.Println("error auth:", value)
		return ""
	}
	return value
}

func (op *OpRouter) Del(item Item) error {
	// http://192.168.1.41/goform/formDhcpListStaticDel
	// delstr: "测试"
	// id: ""
	v := url.Values{}
	gbk_enc := simplifiedchinese.GBK.NewEncoder()
	gbk_dst := make([]byte, 255)
	dst_len, _, err := gbk_enc.Transform(gbk_dst, []byte(item.User), false)
	if err != nil {
		log.Println("transform:", err)
		return err
	}

	v.Add("delstr", string(gbk_dst[:dst_len]))
	v.Add("id", "")

	req, _ := http.NewRequest("POST", "http://192.168.1.41/goform/formDhcpListStaticDel", nil)
	req.Header = http.Header{}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("PostForm del:", err)
		return errors.New("Post Failed")
	}

	if resp.Status == "401 Unauthorized" {
		auth := resp.Header.Get("Www-Authenticate")
		realm := op.GetValue("realm", auth)
		nonce := op.GetValue("nonce", auth)
		opaque := op.GetValue("opaque", auth)

		nonce = g_Config.Nonce

		log.Println("parse succ:", auth, "--", realm, nonce, opaque)

		h1 := md5.Sum([]byte(g_Config.Username + ":" + realm + ":" + g_Config.Password))
		h2 := md5.Sum([]byte("POST:/goform/formDhcpListStaticDel"))
		op.nc++
		op.cnonce = g_Config.Cnonce
		h3_text := fmt.Sprintf("%x:%s:%08d:%s:auth:%x", h1, nonce, op.nc, op.cnonce, h2)

		log.Println("h3_text:", h3_text)
		h3 := md5.Sum([]byte(h3_text))
		log.Println("h3", fmt.Sprintf("%x", h3))

		req_param := fmt.Sprintf("Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"/goform/formDhcpListStaticDel\", qop=\"auth\", algorithm=MD5, nc=%08d, cnonce=\"%s\", response=\"%x\", opaque=\"%s\"",
			realm, nonce, op.nc, op.cnonce, h3, opaque)

		req.Header.Set("Authorization", req_param)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// req.PostForm = v
		form := v.Encode()
		req.Body = ioutil.NopCloser(strings.NewReader(form))
		req.ContentLength = int64(len(form))
		log.Println("REQ:", req)
		resp, err = http.DefaultClient.Do(req)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("PostForm add:", err)
		return errors.New("ioutil read")
	}

	log.Println("DEL_HEAD:", resp.Header)
	log.Println("DEL_CODE:", resp.Status)
	log.Println("DEL_BODY:", string(body))
	return nil
}
func (op *OpRouter) Add(item Item) error {
	// http://192.168.1.41/goform/formDhcpListStatic
	// Action:add
	// UserName: xx
	// IP:"192.168.1.220"
	// UserNameold: xx
	// Mac:""
	v := url.Values{}
	v.Add("Action", "add")

	gbk_enc := simplifiedchinese.GBK.NewEncoder()
	gbk_dst := make([]byte, 255)
	dst_len, _, err := gbk_enc.Transform(gbk_dst, []byte(item.User), false)
	if err != nil {
		log.Println("transform:", err)
		return err
	}

	v.Add("UserName", string(gbk_dst[:dst_len]))
	v.Add("IP", item.IP)
	v.Add("UserNameold", item.User)
	v.Add("Mac", item.Mac)

	req, _ := http.NewRequest("POST", "http://192.168.1.41/goform/formDhcpListStatic", nil)
	req.Header = http.Header{}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("PostForm add:", err)
		return errors.New("Post Failed")
	}

	if resp.Status == "401 Unauthorized" {
		auth := resp.Header.Get("Www-Authenticate")
		realm := op.GetValue("realm", auth)
		nonce := op.GetValue("nonce", auth)
		opaque := op.GetValue("opaque", auth)

		nonce = g_Config.Nonce

		log.Println("parse succ:", auth, "--", realm, nonce, opaque)

		h1 := md5.Sum([]byte(g_Config.Username + ":" + realm + ":" + g_Config.Password))
		h2 := md5.Sum([]byte("POST:/goform/formDhcpListStatic"))
		op.nc++
		op.cnonce = g_Config.Cnonce
		h3_text := fmt.Sprintf("%x:%s:%08d:%s:auth:%x", h1, nonce, op.nc, op.cnonce, h2)

		log.Println("h3_text:", h3_text)
		h3 := md5.Sum([]byte(h3_text))
		log.Println("h3", fmt.Sprintf("%x", h3))

		req_param := fmt.Sprintf("Digest username=\"admin\", realm=\"%s\", nonce=\"%s\", uri=\"/goform/formDhcpListStatic\", qop=\"auth\", algorithm=MD5, nc=%08d, cnonce=\"%s\", response=\"%x\", opaque=\"%s\"",
			realm, nonce, op.nc, op.cnonce, h3, opaque)

		req.Header.Set("Authorization", req_param)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// req.PostForm = v
		form := v.Encode()
		req.Body = ioutil.NopCloser(strings.NewReader(form))
		req.ContentLength = int64(len(form))
		log.Println("REQ:", req)
		resp, err = http.DefaultClient.Do(req)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("PostForm add:", err)
		return errors.New("ioutil read")
	}

	log.Println("HEAD:", resp.Header)
	log.Println("CODE:", resp.Status)
	log.Println("BODY:", string(body))
	return nil
}

type Admin struct {
	file http.Handler
}

func (admin *Admin) Init() {
	admin.file = http.FileServer(http.Dir("static"))
}

func (admin *Admin) ClickPost(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	method := r.FormValue("method")

	log.Println("click:", user, method)

	data := map[string]interface{}{}

	data["Code"] = 0

	for k, v := range g_Storage.Items {
		if v.User == user {
			if method == "pass" {
				err := g_OpRouter.Add(v)
				if err != nil {
					data["Code"] = 2
				} else {
					g_Storage.Items[k].Auth = true
				}
			} else if method == "delete" {
				if g_Storage.Items[k].Auth {
					err := g_OpRouter.Del(v)
					if err != nil {
						data["Code"] = 2
						break
					}
				}
				g_Storage.Items[k].Auth = false
				g_Storage.Items[k].IP = ""
				g_Storage.Items = append(g_Storage.Items[:k], g_Storage.Items[k+1:]...)
			} else if method == "forbid" {
				err := g_OpRouter.Del(v)
				if err != nil {
					data["Code"] = 2
				} else {
					g_Storage.Items[k].Auth = false
				}
			} else {
				data["Code"] = 1
				break
			}
			g_Storage.Save()
			break
		}
	}

	data["Redirect"] = "/adpage.html"

	resp, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(500)
	} else {
		w.Header().Add("Content-Type", "text/json")
		w.Write(resp)
	}
}

func (admin *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	log.Println("REQ:", r.RequestURI)
	if strings.HasPrefix(r.URL.Path, "/static/") {
		r.URL.Path = r.URL.Path[len("/static"):]
		log.Println("CHANGE:", r.URL.Path)
		admin.file.ServeHTTP(w, r)
		return
	}

	if r.Method == "POST" && r.URL.Path == "/click_post.html" {
		admin.ClickPost(w, r)
		return
	}

	if r.RequestURI != "/adpage.html" {
		return
	}

	tmpl, err := template.ParseFiles("template/adpage.html")
	if err != nil {
		log.Println("template: ", err)
		return
	}

	data := map[string]interface{}{}
	data["Items"] = g_Storage.Items
	tmpl.Execute(w, data)
}

func MacShowHandler(w http.ResponseWriter, r *http.Request) {
	var item Item

	log.Println("remote:", r.RemoteAddr)

	user := r.FormValue("user")
	if len(user) == 0 {
		log.Println("user:", user)
		return
	}

	off := strings.Index(r.RemoteAddr, ":")
	if off == -1 {
		w.Write([]byte("error:" + r.RemoteAddr))
		return
	}

	log.Println("remote addr:", r.RemoteAddr[:off])

	mac, err := tools.ShowMac(r.RemoteAddr[:off])
	if err != nil || mac == "" {
		log.Println("MacShow failed:", err.Error(), mac)

		Message := "MAC地址获取失败"
		tmpl, _ := template.ParseFiles("template/resp.html")
		tmpl.Execute(w, Message)
		return
	}

	item.Auth = false
	item.Mac = mac
	item.User = user
	item.IP = r.RemoteAddr[:off]

	/*
		for i := g_Storage.Base; i < 200; i++ {
			item.IP = g_Storage.Prefix + strconv.Itoa(i)

			repeat := false
			for _, v := range g_Storage.Items {
				if v.IP == item.IP {
					repeat = true
					break
				}
			}
			if !repeat {
				break
			}
		}
	*/

	Message := ""
	for _, v := range g_Storage.Items {
		/*if v.IP == item.IP {
			Message = "没有可用IP"
			break
		} else*/if v.Mac == item.Mac {
			Message = "机器已经申请过"
			break
		} else if v.User == item.User {
			Message = "用户名重复"
			break
		}
	}
	if len(Message) == 0 {
		Message = "申请成功，请等待审批..."
		g_Storage.Items = append(g_Storage.Items, item)
		g_Storage.Save()
	}

	log.Println("succ", item)
	tmpl, _ := template.ParseFiles("template/resp.html")
	tmpl.Execute(w, Message)
}

func main() {
	data, err := ioutil.ReadFile("config/config.json")
	if err != nil {
		log.Println("Load Config:", err)
		return
	}

	err = json.Unmarshal(data, &g_Config)
	if err != nil {
		log.Println("Unmarshal:", err)
		return
	}

	admin := Admin{}
	admin.Init()

	g_Storage.Base = 150
	g_Storage.Prefix = "192.168.1."
	g_Storage.Load()

	http.HandleFunc("/reg.html", RegPageHandler)
	http.HandleFunc("/mac.html", MacShowHandler)

	go http.ListenAndServe("127.0.0.1:9000", &admin)

	http.ListenAndServe("192.168.1.105:8080", nil)
	// http.ListenAndServe("127.0.0.1:8080", nil)
}
