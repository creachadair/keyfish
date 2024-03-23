package main

import (
	"github.com/creachadair/keyfish/kfdb"
	"github.com/creachadair/keyfish/kflib"
)

func genPassword(db *kfdb.DB, tag string, rec *kfdb.Record) (string, error) {
	hc := kflib.GetHashpassInfo(db, rec, tag)
	if hc.Format != "" {
		return hc.Context.Format(hc.Format), nil
	}
	return hc.Password(hc.Length), nil
}
