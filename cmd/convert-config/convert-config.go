package main

import (
	"flag"
	"log"
	"os"
	"sort"

	"github.com/creachadair/keyfish/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/value"
	"github.com/creachadair/otp/otpauth"
)

var (
	saveSecret = flag.Bool("save-secret-key", false,
		"Save the hashpass generation secret as a default")
	genHashKeys = flag.Bool("generate-hashpass-keys", false,
		"Generate and store hashpass keys for each record")
	dropHashConfig = flag.Bool("drop-hashpass-config", false,
		"Do not convert hashpass configuration")

	configPath = flag.String("config", config.FilePath(), "Input config file path (required)")
	dbPath     = flag.String("db", "", "Output database file path (required)")
)

func main() {
	flag.Parse()
	switch {
	case *configPath == "":
		log.Fatal("You must provide an input --config path")
	case *dbPath == "":
		log.Fatal("You must provide an output --db path")
	case *dropHashConfig && !*genHashKeys:
		log.Print("WARNING: You set --drop-hashpass-config but not --generate-hashpass-keys")
	}

	if _, err := os.Stat(*dbPath); err == nil {
		log.Fatalf("Output file %q already exists", *dbPath)
	}

	// Default settings from keyfish.go
	base := &config.Config{
		Default: config.Site{Length: 18, Punct: value.Ptr(true)},
	}
	if err := base.Load(*configPath); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}
	log.Printf("Loaded configuration from %s", *configPath)

	var secretKey string
	if *saveSecret || *genHashKeys {
		key, err := kflib.ConfirmPassphrase("Secret key: ")
		if err != nil {
			log.Fatalf("Reading secret key: %v", err)
		}
		secretKey = key
	}

	db := &kfdb.DB{
		Records:  make(map[string]*kfdb.Record),
		Defaults: new(kfdb.Defaults),
	}
	if err := db.MarshalSettings("flags", base.Flags); err != nil {
		log.Fatalf("Encoding flags: %v", err)
	}
	hps := &kfdb.Hashpass{Punct: base.Default.Punct}
	if *saveSecret {
		hps.SecretKey = secretKey
	}

	// Copy default settings.
	if base.Default.EMail != "" {
		db.Defaults.Addr = base.Default.EMail
	}
	if base.Default.Length > 0 {
		db.Defaults.PasswordLength = base.Default.Length
	}
	if base.Default.Login != "" {
		db.Defaults.Username = base.Default.Login
	}
	if *hps != (kfdb.Hashpass{}) {
		db.Defaults.Hashpass = hps
	}

	// If we did not update any default settings, drop that message.
	if *db.Defaults == (kfdb.Defaults{}) {
		db.Defaults = nil
	}

	// Transcribe sites.
	for id, orig := range base.Sites {
		// Merge in defaults and other expansions done in the old config.
		// However, as a special case, don't copy $EMAIL logins to the username.
		site, _ := base.Site(id)
		if orig.Login == "$EMAIL" {
			site.Login = ""
		}
		rec := &kfdb.Record{
			Title:    site.Title,
			Username: site.Login,
			Hosts:    kfdb.Strings{site.Host},
			Details:  site.Hints,
			Hashpass: &kfdb.Hashpass{
				Seed:   site.Key,
				Length: site.Length,
				Format: site.Format,
				Tag:    site.Salt,
				Punct:  site.Punct,
			},
		}

		// If the user asked to save the generated keys, run the generator and
		// store the output directly in the record.
		if *genHashKeys {
			if site.Format != "" {
				rec.Password = site.Context(secretKey).Format(site.Format)
			} else {
				rec.Password = site.Context(secretKey).Password(site.Length)
			}
		}

		rec.Hosts = append(rec.Hosts, site.Aliases...)

		// Remove per-record settings that are identical to the defaults.
		if rec.Hashpass.Length == base.Default.Length {
			rec.Hashpass.Length = 0
		}
		if sp, bp := site.Punct, base.Default.Punct; sp != nil && bp != nil && *sp == *bp {
			rec.Hashpass.Punct = nil
		}
		if *rec.Hashpass == (kfdb.Hashpass{}) || *dropHashConfig {
			rec.Hashpass = nil
		}
		if orig.EMail != "" { // unexpanded
			rec.Addrs = kfdb.Strings{site.EMail} // expanded
		}

		// Check for OTP codes. A site default goes into the main record, but if
		// there are additional ones stuff them into the details for now.
		var extraOTP []*otpauth.URL
		for name, otp := range site.OTP {
			if name == "" || len(site.OTP) == 1 { // site default
				rec.OTP = otpToURL("", id, otp)
				continue
			}
			extraOTP = append(extraOTP, otpToURL(name, id, otp))
		}
		if len(extraOTP) != 0 {
			if rec.Details == nil {
				rec.Details = make(map[string]any)
			}
			rec.Details["extra-otp"] = extraOTP
		}

		// Check for salt labels, and copy these to the tags.
		if sr, ok := site.Hints["salts"]; ok {
			ss, _ := sr.(map[string]any)
			for key := range ss {
				rec.Tags = append(rec.Tags, key)
			}
		}
		sort.Strings(rec.Tags)

		// Check for notes and move them to the main record.
		if n, ok := site.Hints["notes"]; ok {
			if val, ok := n.(string); ok {
				rec.Notes = val
				delete(site.Hints, "notes")
			}
		}

		db.Records[id] = rec
	}

	pp, err := kflib.ConfirmPassphrase("Passphrase: ")
	if err != nil {
		log.Fatalf("Reading passphrase: %v", err)
	}

	s, err := kfdb.New(pp, db)
	if err != nil {
		log.Fatalf("Create database: %v", err)
	} else if err := kflib.SaveDB(s, *dbPath); err != nil {
		log.Fatalf("Write database: %v", err)
	}
	log.Printf("Wrote database to %s", *dbPath)
}

func otpToURL(id, who string, otp *config.OTP) *otpauth.URL {
	url := &otpauth.URL{Type: "totp", Account: who, Issuer: id}
	url.SetSecret(otp.Key)
	return url
}
