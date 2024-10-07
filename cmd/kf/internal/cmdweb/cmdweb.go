// Package cmdweb implements the "web" subcommand.
package cmdweb

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/mds/value"
	"github.com/creachadair/otp/otpauth"
)

var Command = &command.C{
	Name:     "web",
	Help:     "Run a server for the keyfish web app.",
	SetFlags: command.Flags(flax.MustBind, &serverFlags),
	Run:      command.Adapt(runServer),
}

var serverFlags struct {
	Addr     string `flag:"addr,Service address (host:port)"`
	AutoLock bool   `flag:"autolock,Automatically lock the UI when idle"`
	Expert   bool   `flag:"expert,PRIVATE:Enable expert UI"`
}

func runServer(env *command.Env) error {
	if serverFlags.Addr == "" {
		return env.Usagef("you must provide a service --addr")
	}
	w, err := config.WatchDB(env)
	if err != nil {
		return err
	}
	dbDefaults := value.At(w.Store().DB().Defaults)
	webConfig := value.At(dbDefaults.Web)
	ui := &UI{
		Store:       w.Store,
		Static:      staticFS,
		Templates:   ui,
		LockTimeout: cmp.Or(webConfig.LockTimeout.Get(), 2*time.Minute),
		Expert:      serverFlags.Expert,
	}
	if serverFlags.AutoLock {
		if webConfig.LockPIN == "" {
			return env.Usagef("no lock PIN is defined for --autolock")
		}
		ui.Locked = true
		ui.LockPIN = webConfig.LockPIN
	}
	srv := &http.Server{
		Addr:    serverFlags.Addr,
		Handler: ui.ServeMux(),
	}
	ctx, cancel := signal.NotifyContext(env.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		log.Printf("Watching for updates at %q", config.DBPath(env))
		w.Run(ctx)
	}()
	go func() {
		log.Printf("Serving at %q", serverFlags.Addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("WARNING: Server error %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("Signal received, stopping server")
	return srv.Shutdown(context.Background())
}

// To update the HTMX version, edit the URL here.
//go:generate curl -sL -o static/htmx.min.js https://unpkg.com/htmx.org@v2.0.3/dist/htmx.min.js

//go:embed static
var staticFS embed.FS

//go:embed templates
var tmplFS embed.FS

var ui = template.Must(template.New("ui").Funcs(map[string]any{
	"isOTP": func(s string) bool {
		if !strings.HasPrefix(s, "otpauth:") {
			return false
		}
		_, err := otpauth.ParseURL(s)
		return err == nil
	},
	"formatText": func(s string) any {
		return template.HTML(strings.ReplaceAll(template.HTMLEscapeString(s), "\n", "<br />\n"))
	},
	"toURL": func(s string) string {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" {
			return "https://" + s
		}
		return u.String()
	},
}).ParseFS(tmplFS, "templates/*"))
