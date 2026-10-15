package main

import (
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

func sqli(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM u WHERE n = '" + name + "'") // VULN sqli
	db.Query("SELECT * FROM u WHERE n = ?", name)          // SAFE
}

func cmd(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	exec.Command("sh", "-c", "ping "+host).Run() // VULN cmdi
}

func file(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	os.ReadFile(filepath.Join("/data", f))                // VULN path
	os.ReadFile(filepath.Join("/data", filepath.Base(f))) // SAFE
}

func xss(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
	fmt.Fprintf(w, "<b>%s</b>", q)                   // VULN xss
	fmt.Fprintf(w, "<b>%s</b>", html.EscapeString(q)) // SAFE
}

func ssrf(w http.ResponseWriter, r *http.Request) {
	http.Get(r.URL.Query().Get("url")) // VULN ssrf
}
