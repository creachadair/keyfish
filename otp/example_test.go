package otp_test

import (
	"crypto/sha256"
	"fmt"

	"bitbucket.org/creachadair/keyfish/otp"
)

func Example() {
	cfg := otp.Config{
		Key:    "44b56d71-07e4-40db-a36b-215ebcea0164",
		Hash:   sha256.New, // default is sha1.New
		Digits: 8,          // default is 6

		// By default, time-based OTP generation uses time.Now.  You can plug in
		// your own function to control how time steps are generated.
		// This example uses a fixed time step so the output will be consistent.
		TimeStep: func() uint64 { return 1 },
	}

	fmt.Println("HOTP", 0, cfg.HOTP(0))
	fmt.Println("HOTP", 1, cfg.HOTP(1))
	fmt.Println()
	fmt.Println("TOTP", cfg.TOTP())
	// Output:
	// HOTP 0 35517826
	// HOTP 1 04957339
	//
	// TOTP 04957339
}
