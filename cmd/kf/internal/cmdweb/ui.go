package cmdweb

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/slice"
	"github.com/creachadair/otp/otpauth"
)

// UI implements the HTTP endpoints for the Keyfish web UI.
type UI struct {
	// Store returns the active instance of the store to serve.
	Store func() *kfdb.Store

	// Static is the filesystem containing static file assets.
	Static fs.FS

	// Templates are the compiled UI templates.
	Templates *template.Template

	// LockPIN, if non-empty, is the PIN used to unlock a locked UI.
	LockPIN string

	// Locked, if true, is whether the UI is (currently) locked.
	Locked bool
}

// ServeMux returns a router for the UI endpoints:
//
//	GET /static/  -- serve static assets
//	GET /         -- serve the main UI page
//	GET /search   -- serve search results (partial)
//	GET /view     -- serve a single record view (partial)
//	GET /detail   -- serve a single record detail (partial)
//	GET /password -- serve a single record password (partial)
//	GET /totp     -- serve a single record TOTP code (partial)
//	GET /unlock   -- request an unlock of the UI
func (s *UI) ServeMux() http.Handler {
	mux := http.NewServeMux()
	if s.Static != nil {
		mux.Handle("GET /static/", http.FileServer(http.FS(s.Static)))
	}
	mux.HandleFunc("GET /{$}", addCSP(s.ui))
	mux.HandleFunc("GET /search", addCSP(s.checkLock(s.search)))
	mux.HandleFunc("GET /view/{id}", addCSP(s.checkLock(s.view)))
	mux.HandleFunc("GET /detail/{id}/{index}", addCSP(s.checkLock(s.detail)))
	mux.HandleFunc("GET /password/{id}", addCSP(s.checkLock(s.password)))
	mux.HandleFunc("GET /totp/{id}", addCSP(s.checkLock(s.totp)))
	if s.LockPIN != "" {
		mux.HandleFunc("GET /lock", addCSP(s.lock))
		mux.HandleFunc("GET /unlock", addCSP(s.unlock))
	}
	return mux
}

// runTemplate invokes the named template with the specified argument value.
// If the template reports an error, runTemplates serves a 500.
func (s *UI) runTemplate(w http.ResponseWriter, r *http.Request, name string, value any) {
	var buf bytes.Buffer
	if err := s.Templates.Lookup(name).Execute(&buf, value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// ui serves the main UI page.
func (s *UI) ui(w http.ResponseWriter, r *http.Request) {
	u := uiData{CanLock: s.LockPIN != "", Locked: s.Locked}
	if query := strings.TrimSpace(r.FormValue("q")); query != "" {
		if query != "*" && query != "?" {
			u.Query = query
		}
		u.SearchResult = searchRecords(s.Store().DB().Records, u.Query)
	}
	s.runTemplate(w, r, "index.html.tmpl", u)
}

// search serves search results (partial).
func (s *UI) search(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.FormValue("q"))
	switch query {
	case "":
		return // no results, empty response
	case "*", "?":
		query = "" // find everything
	default:
	}
	s.runTemplate(w, r, "search.html.tmpl", uiData{
		SearchResult: searchRecords(s.Store().DB().Records, query),
	})
}

// view serves a record view (partial).
func (s *UI) view(w http.ResponseWriter, r *http.Request) {
	st := s.Store()
	index, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid ID", http.StatusBadRequest)
		return
	} else if index < 0 || index >= len(st.DB().Records) {
		http.Error(w, "no such record ID", http.StatusNotFound)
		return
	}
	s.runTemplate(w, r, "view.html.tmpl", uiData{
		TargetRecord: &uiRecord{
			Index:  index,
			Record: st.DB().Records[index],
		},
	})
}

// detail serves a record detail view (partial).  This is only called for
// details marked as "hidden".
func (s *UI) detail(w http.ResponseWriter, r *http.Request) {
	id, err1 := strconv.Atoi(r.PathValue("id"))
	index, err2 := strconv.Atoi(r.PathValue("index"))
	if err1 != nil || err2 != nil {
		http.Error(w, "invalid ID/index", http.StatusBadRequest)
		return
	}
	st := s.Store()
	if id < 0 || id >= len(st.DB().Records) {
		http.Error(w, "no such record ID", http.StatusNotFound)
		return
	}
	rec := st.DB().Records[id]
	if index < 0 || index >= len(rec.Details) {
		http.Error(w, "no such detail index", http.StatusNotFound)
		return
	}
	tag := fmt.Sprintf("r%dd%d", id, index)
	det := rec.Details[index]

	// N.B. Capitalization of HX matters here.
	w.Header().Set("HX-Trigger-After-Settle", fmt.Sprintf(`{"setValueToggle":"%s"}`, tag))
	s.runTemplate(w, r, "detail.html.tmpl", uiDetail{
		RecordID: id,
		DetailID: index,
		ID:       tag,
		Label:    det.Label,
		Value:    det.Value,
	})
}

// password serves a record password fragment (partial).
// It serves a storedpassword if one is available, otherwise it falls back to a
// hashpass. If hashpass=1 is set it always produces a hashpass.
func (s *UI) password(w http.ResponseWriter, r *http.Request) {
	st := s.Store()
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid ID", http.StatusBadRequest)
		return
	} else if id < 0 || id >= len(st.DB().Records) {
		http.Error(w, "no such record ID", http.StatusNotFound)
		return
	}
	preferHash, _ := strconv.ParseBool(r.FormValue("hashpass"))

	rec := st.DB().Records[id]
	var pw string
	if rec.Password != "" && !preferHash {
		pw = rec.Password
	} else {
		pw, err = kflib.GenerateHashpass(st.DB(), rec, r.FormValue("tag"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("HX-Trigger-After-Settle", `{"copyText":"pwval"}`)
	s.runTemplate(w, r, "pass.html.tmpl", uiDetail{ID: "pwval", Value: pw})
}

// totp serves a record TOTP fragment (partial).
// It reports an error if the record does not have an OTP configuration.
func (s *UI) totp(w http.ResponseWriter, r *http.Request) {
	st := s.Store()
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid ID", http.StatusBadRequest)
		return
	} else if id < 0 || id >= len(st.DB().Records) {
		http.Error(w, "no such record ID", http.StatusNotFound)
		return
	}
	rec := st.DB().Records[id]
	u, field := rec.OTP, "otpval"
	if det, err := strconv.Atoi(r.FormValue("detail")); err == nil {
		if det < 0 || det >= len(rec.Details) {
			http.Error(w, "no such detail", http.StatusNotFound)
			return
		}
		u, err = otpauth.ParseURL(rec.Details[det].Value)
		if err != nil {
			http.Error(w, "detail is not an OTP", http.StatusGone)
			return
		}
		field = fmt.Sprintf("r%dd%dotp", id, det)
	} else if u == nil {
		http.Error(w, "no OTP configuration", http.StatusNotFound)
		return
	}
	otp, err := kflib.GenerateOTP(u, 0)
	if err != nil {
		http.Error(w, "unable to generate OTP", http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger-After-Settle", fmt.Sprintf(`{"copyText":"%s"}`, field))
	s.runTemplate(w, r, "pass.html.tmpl", uiDetail{ID: field, Value: otp})
}

// lock requests a lock of the UI.  It redirects to the UI.
func (s *UI) lock(w http.ResponseWriter, r *http.Request) {
	s.Locked = true
	http.Redirect(w, r, "/", http.StatusFound)
}

// unlock requests an unlock of the UI.  It redirects to the UI if it is not
// locked, or reports an error if the specified PIN does not match.
func (s *UI) unlock(w http.ResponseWriter, r *http.Request) {
	if s.Locked && r.FormValue("lockpin") != s.LockPIN {
		http.Error(w, "invalid PIN", http.StatusForbidden)
		return
	}
	s.Locked = false
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *UI) checkLock(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Locked {
			http.Error(w, "UI is locked", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// contentSecurityPolicy is the CSP header we send to client browsers.
var contentSecurityPolicy = strings.Join([]string{
	`base-uri 'self'`,
	`block-all-mixed-content`,
	`default-src 'self'`,
	`form-action 'self'`,
	`frame-ancestors 'none'`,
}, "; ")

func addCSP(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		h.ServeHTTP(w, r)
	}
}

func searchRecords(recs []*kfdb.Record, query string) []kflib.FoundRecord {
	return slice.Partition(kflib.FindRecords(recs, query), func(fr kflib.FoundRecord) bool {
		return !fr.Record.Archived
	})
}

type uiData struct {
	Query        string
	SearchResult []kflib.FoundRecord
	TargetRecord *uiRecord
	CanLock      bool // whether locking is enabled
	Locked       bool // whether the UI is locked now
}

type uiRecord struct {
	Index  int
	Record *kfdb.Record
}

type uiDetail struct {
	RecordID int
	DetailID int
	ID       string
	Label    string
	Value    string
}
