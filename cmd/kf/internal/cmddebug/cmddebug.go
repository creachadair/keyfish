// Package cmddebug implements the "kf debug" subcommand.
package cmddebug

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/keyfish/cmd/kf/config"
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
	"github.com/creachadair/mds/value"
	"github.com/creachadair/otp/otpauth"
)

var Command = &command.C{
	Name: "debug",
	Help: `Debug commands (potentially dangerous).

Debug commands require specifying a database path explicitly.
Use "@" to refer to the path set via the --db flag.`,

	Unlisted: true,

	Commands: []*command.C{
		{
			Name:  "export",
			Usage: "<db-path>",
			Help:  "Export the contents of a database in plaintext as JSON.",
			Run:   command.Adapt(runDebugExport),
		},
		{
			Name:  "import",
			Usage: "<db-path> <json-path>",
			Help:  "Import a plaintext JSON into a database, replacing its contents.",
			Run:   command.Adapt(runDebugImport),
		},
		{
			Name:  "hashpass",
			Usage: "[flags] [salt]@seed",
			Help: `Generate an HKDF based hashed password.

The seed is the non-secret generator seed. If provided, the salt is
mixed in to the HKDF as additional context. The user is prompted for
the HKDF secret. The output is written as a single line to stdout.`,
			SetFlags: command.Flags(flax.MustBind, &hpFlags),
			Run:      command.Adapt(runDebugHashpass),
		},
		{
			Name:     "totp",
			Usage:    "[flags] <otp-secret>",
			Help:     "Generate an initial TOTP code and an OTP URL.",
			SetFlags: command.Flags(flax.MustBind, &otpFlags),
			Run:      command.Adapt(runDebugTOTP),
		},
	},
}

// runDebugExport implements the "debug export" subcommand.
func runDebugExport(env *command.Env, dbPath string) error {
	s, err := kflib.OpenDB(getDBPath(env, dbPath))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(s.DB())
}

// runDebugImport implements the "debug import" subcommand.
func runDebugImport(env *command.Env, dbPath, jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("load JSON: %w", err)
	}
	var db kfdb.DB
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	dp := getDBPath(env, dbPath)
	s, err := kflib.OpenDB(dp)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	*s.DB() = db
	if err := kflib.SaveDB(s, dp); err != nil {
		return err
	}
	fmt.Fprintf(env, "Imported %q into %q\n", jsonPath, dp)
	return nil
}

var hpFlags struct {
	Length  int  `flag:"n,The length of the password to generate"`
	NoDigit bool `flag:"no-digits,Omit digits from the generated password"`
	Symbols bool `flag:"symbols,Include punctuation in the generated password"`
	Confirm bool `flag:"c,Confirm passphrase"`
}

// runDebugHashpass implements the "debug hashpass" subcommand.
func runDebugHashpass(env *command.Env, input string) error {
	if hpFlags.Length <= 0 {
		return env.Usagef("the length (-n) must be positive")
	}

	salt, seed, ok := strings.Cut(input, "@")
	if !ok {
		salt, seed = "", input
	}
	pp, err := value.Cond(hpFlags.Confirm, kflib.ConfirmPassphrase, kflib.GetPassphrase)("Passphrase: ")
	if err != nil {
		return err
	}
	cs := kflib.Letters
	if !hpFlags.NoDigit {
		cs |= kflib.Digits
	}
	if hpFlags.Symbols {
		cs |= kflib.Symbols
	}
	fmt.Println(kflib.HashedChars(hpFlags.Length, cs, pp, seed, salt))
	return nil
}

var otpFlags struct {
	Account string `flag:"account,The name of the account"`
	Issuer  string `flag:"issuer,The issuer of the TOTP secret"`
	Digits  int    `flag:"digits,Number of code digits to generate"`
	Codes   int    `flag:"codes,default=1,Number of codes to generate"`
	Period  int    `flag:"period,default=30,Code generation interval in seconds"`
}

// runDebugTOTP implements the "debug totp" subcommand.
func runDebugTOTP(env *command.Env, secret []string) error {
	key := strings.TrimSpace(strings.Join(strings.Fields(strings.Join(secret, "")), ""))
	if key == "" {
		return env.Usagef("you must provide a base32-encoded secret")
	}
	u := &otpauth.URL{
		Type:      "totp",
		Issuer:    otpFlags.Issuer,
		Account:   otpFlags.Account,
		Digits:    otpFlags.Digits,
		Period:    otpFlags.Period,
		RawSecret: key,
	}
	fmt.Println("URL:", u)
	for i := range otpFlags.Codes {
		code, err := kflib.GenerateOTP(u, i)
		if err != nil {
			return fmt.Errorf("generate OTP code: %w", err)
		}
		fmt.Println("OTP:", code)
	}
	return nil
}

func getDBPath(env *command.Env, dbPath string) string {
	if dbPath == "@" {
		return config.DBPath(env)
	}
	return dbPath
}
