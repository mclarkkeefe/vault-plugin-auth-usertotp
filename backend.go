package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	totpPrefix string = "/totp/"
	userPrefix string = "users/"
)

type backend struct {
	*framework.Backend
}

func Backend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		AuthRenew:   b.pathLoginRenew,
		BackendType: logical.TypeCredential,
		Help:        "The usertotp backend is an auth backend that stores and authenticates using a user using a pin and TOTP code token.",
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathUsers(b),
				pathUsersUsername(b),
				pathUsersUsernameTOTP(b),
			},
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/*",
			},
		},
	}

	return b
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}
