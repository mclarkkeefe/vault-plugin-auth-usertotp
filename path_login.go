package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/bcrypt"
)

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Description: "Username of the user.",
				Type:        framework.TypeLowerCaseString,
			},
			"password": {
				Description: "Concatenated PIN and TOTP for the user.",
				Type:        framework.TypeString,
			},
		},
		HelpSynopsis: `
Log in with a username and pin+totp.
`,
		HelpDescription: `
Log in This endpoint authenticates using a username and pin+totp.
`,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.pathLoginAliasLookahead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathLogin,
			},
		},
		Pattern: `login/` + framework.GenericNameRegex("username"),
	}
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return logical.ErrorResponse("missing username"), nil
	}

	password := d.Get("password").(string)
	if password == "" {
		return logical.ErrorResponse("missing password"), nil
	}

	user, err := b.getUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return logical.ErrorResponse("user %q could not be found", username), nil
	}

	pin, code, err := getPinHashTOTPCode(password)
	if err != nil {
		return logical.ErrorResponse("user %q does not have a matching pintotp", username), nil
	}

	success := false

	for _, totp := range user.TOTPTokens {
		tokenCode, err := getTOTPCodeFromTOTPSecret(totp.Secret)
		if err != nil {
			return nil, err
		}

		if bcrypt.CompareHashAndPassword(totp.PinHash, []byte(pin)) == nil && code == tokenCode {
			if len(totp.TokenBoundCIDRs) > 0 {
				if req.Connection == nil {
					return logical.ErrorResponse("can't compare token, no connection information provided"), nil
				}

				if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, user.TokenBoundCIDRs) {
					return nil, logical.ErrPermissionDenied
				}
			}

			success = true
			break
		}
	}

	if !success {
		return logical.ErrorResponse("user %q does not have a matching token", username), nil
	}

	if len(user.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			return logical.ErrorResponse("can't compare token, no connection information provided"), nil
		}

		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, user.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	auth := &logical.Auth{
		Alias: &logical.Alias{
			Name: username,
		},
		DisplayName: username,
		Metadata: map[string]string{
			"username": username,
		},
	}

	user.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return logical.ErrorResponse("missing username"), nil
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.getUser(ctx, req.Storage, req.Auth.Metadata["username"])
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, nil
	}

	if !policyutil.EquivalentPolicies(user.TokenPolicies, req.Auth.TokenPolicies) {
		return nil, fmt.Errorf("not renewing due to policy changes")
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.MaxTTL = user.TokenMaxTTL
	resp.Auth.Period = user.TokenPeriod
	resp.Auth.TTL = user.TokenTTL

	return resp, nil
}
