package cmdconvert

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/internal/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/value"
	"github.com/creachadair/otp/otpauth"
)

var convertFlags struct {
	SaveSecret     bool `flag:"save-secret-key,Save the hashpass generation secret as a default"`
	GenHashKeys    bool `flag:"generate-hashpass-keys,Generate and store hashpass keys for each record"`
	DropHashConfig bool `flag:"drop-hashpass-config,Skip conversion of hashpass configurations"`
}

var Command = &command.C{
	Name:     "convert",
	Usage:    "<config-path> <database-path>",
	Help:     "Convert an old-style Keyfish JSON config to an encrypted database.",
	SetFlags: command.Flags(flax.MustBind, &convertFlags),
	Run:      command.Adapt(runConvert),
}

func runConvert(env *command.Env, configPath, dbPath string) error {
	if _, err := os.Stat(dbPath); err == nil {
		return fmt.Errorf("output %q already exists", dbPath)
	}

	// Default settings from keyfish.go
	base := &config.Config{
		Default: config.Site{Length: 18, Punct: value.Ptr(true)},
	}
	if err := base.Load(configPath); err != nil {
		return fmt.Errorf("loading keyfish config: %w", err)
	}
	log.Printf("Loaded configuration from %s", configPath)

	var secretKey string
	if convertFlags.SaveSecret || convertFlags.GenHashKeys {
		key, err := kflib.ConfirmPassphrase("Secret key: ")
		if err != nil {
			log.Fatalf("Reading secret key: %v", err)
		}
		secretKey = key
	}

	db := &kfdb.DB{Defaults: new(kfdb.Defaults)}
	if err := db.MarshalSettings("flags", base.Flags); err != nil {
		return fmt.Errorf("encoding flags: %w", err)
	}
	hps := &kfdb.Hashpass{Punct: base.Default.Punct}
	if convertFlags.SaveSecret {
		hps.SecretKey = secretKey
	}

	// Copy default settings.
	if base.Default.EMail != "" {
		db.Defaults.Addr = base.Default.EMail
	}
	if base.Default.Length > 0 {
		db.Defaults.Hashpass.Length = base.Default.Length
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
			Label:    id,
			Title:    site.Title,
			Username: site.Login,
			Hosts:    kfdb.Strings{site.Host},
			Archived: site.Archived,
			Hashpass: &kfdb.Hashpass{
				Seed:   site.Key,
				Length: site.Length,
				Format: site.Format,
				Tag:    site.Salt,
				Punct:  site.Punct,
			},
		}

		// Check for notes and move them to the main record.
		if n, ok := site.Hints["notes"]; ok {
			if val, ok := n.(string); ok {
				rec.Notes = val
				delete(site.Hints, "notes")
			}
		}

		// Any other hints become details.
		for key, val := range site.Hints {
			var s string
			switch t := val.(type) {
			case string:
				s = t
			case map[string]any:
				var sb strings.Builder
				for vkey, vval := range t {
					s, ok := vval.(string)
					if !ok {
						bits, _ := json.Marshal(vval)
						s = string(bits)
					}
					fmt.Fprintf(&sb, "%s: %s\n", vkey, s)
				}
				rec.Details = append(rec.Details, &kfdb.Detail{
					Label: key,
					Value: strings.TrimSpace(sb.String()),
				})
				continue
			default:
				bits, _ := json.Marshal(val)
				log.Printf("WARNING: Encoding value for hint %q as JSON", key)
				s = string(bits)
			}
			key, hidden := strings.CutPrefix(key, "$")
			rec.Details = append(rec.Details, &kfdb.Detail{
				Label: key, Hidden: hidden, Value: s,
			})
		}

		// If the user asked to save the generated keys, run the generator and
		// store the output directly in the record.
		if convertFlags.GenHashKeys {
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
		if *rec.Hashpass == (kfdb.Hashpass{}) || convertFlags.DropHashConfig {
			rec.Hashpass = nil
		}
		if orig.EMail != "" { // unexpanded
			rec.Addrs = kfdb.Strings{site.EMail} // expanded
		}

		// Check for OTP codes. A site default goes into the main record, but if
		// there are additional ones stuff them into the details for now.
		for name, otp := range site.OTP {
			if name == "" || len(site.OTP) == 1 { // site default
				rec.OTP = otpToURL("", id, otp)
				continue
			}
			rec.Details = append(rec.Details, &kfdb.Detail{
				Label:  fmt.Sprintf("OTP for %s", name),
				Hidden: true,
				Value:  otpToURL(name, id, otp).String(),
			})
		}
		slices.SortFunc(rec.Details, func(a, b *kfdb.Detail) int {
			return cmp.Compare(a.Label, b.Label)
		})

		// Check for salt labels, and copy these to the tags.
		if sr, ok := site.Hints["salts"]; ok {
			ss, _ := sr.(map[string]any)
			for key := range ss {
				rec.Tags = append(rec.Tags, key)
			}
		}
		slices.Sort(rec.Tags)

		db.Records = append(db.Records, rec)
	}
	slices.SortFunc(db.Records, func(a, b *kfdb.Record) int {
		return cmp.Compare(a.Label, b.Label)
	})

	pp, err := kflib.ConfirmPassphrase("Passphrase: ")
	if err != nil {
		log.Fatalf("Reading passphrase: %v", err)
	}

	s, err := kfdb.New(pp, db)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	} else if err := kflib.SaveDB(s, dbPath); err != nil {
		return fmt.Errorf("write database: %w", err)
	}
	fmt.Printf("Wrote database to %q\n", dbPath)
	return nil
}

func otpToURL(id, who string, otp *config.OTP) *otpauth.URL {
	url := &otpauth.URL{Type: "totp", Account: who, Issuer: id}
	url.SetSecret(otp.Key)
	return url
}
