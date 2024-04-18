// Package cmdserver implements the web application server subcommand.
package cmdserver

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/otp/otpauth"
)

var Command = &command.C{
	Name:     "server",
	Help:     "Run a server for the keyfish web app.",
	SetFlags: command.Flags(flax.MustBind, &serverFlags),
	Run:      command.Adapt(runServer),
}

var serverFlags struct {
	Addr string `flag:"addr,Service address (host:port)"`
}

func runServer(env *command.Env) error {
	if serverFlags.Addr == "" {
		return env.Usagef("you must provide a service --addr")
	}
	w, err := kflib.OpenDBWatcher(config.DBPath(env))
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: serverFlags.Addr,
		Handler: UI{
			Store:     w.Store,
			Static:    staticFS,
			Templates: ui,
		}.ServeMux(),
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

//go:generate curl -sL -o static/htmx.min.js https://unpkg.com/htmx.org/dist/htmx.min.js

//go:embed static
var staticFS embed.FS

//go:embed templates
var tmplFS embed.FS

var ui = template.Must(template.New("ui").Funcs(map[string]any{
	"isOTP": func(s string) bool {
		_, err := otpauth.ParseURL(s)
		return err == nil
	},
}).ParseFS(tmplFS, "templates/*"))