package main

import (
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
)

func getPinHashTOTPCode(pintoken string) (pin string, code string, err error) {
	if len(pintoken) < 7 {
		err = errors.New("pintoken has invalid length")
		return
	}

	pin = pintoken[:len(pintoken)-6]
	code = pintoken[len(pintoken)-6:]

	return pin, code, nil
}

func getTOTPCodeFromTOTPSecret(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}
