package cmdcli

import (
	"strings"

	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/otp/otpauth"
)

func getOTPCode(rec *kfdb.Record, tag string) *otpauth.URL {
	if tag == "" {
		return rec.OTP
	}
	for _, d := range rec.Details {
		if !strings.Contains(d.Label, tag) {
			continue
		}
		if u, err := otpauth.ParseURL(d.Value); err == nil {
			return u
		}
	}
	return rec.OTP
}
