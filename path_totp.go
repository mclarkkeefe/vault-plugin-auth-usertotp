package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type totpEntry struct {
	tokenutil.TokenParams
	Name    string `json:"name"`
	PinHash []byte `json:"pin_hash"`
	Secret  string `json:"secret"`
}

func pathUsersUsernameTOTP(b *backend) *framework.Path {
	return &framework.Path{
		HelpDescription: "",
		HelpSynopsis:    "",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeLowerCaseString,
				Description: "Username for this user.",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Unique name of the token.",
			},
			"pin": {
				Type:        framework.TypeString,
				Description: "PIN for the TOTP token",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathTOTPCreate,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathTOTPDelete,
			},
		},
		Pattern: userPrefix + framework.GenericNameRegex("username") + "/totp$",
	}
}

func (b *backend) pathTOTPCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return logical.ErrorResponse("username not found"), nil
	}

	user, err := b.getUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return logical.ErrorResponse("username not found"), nil
	}

	newToken := totpEntry{}
	newToken.Name = d.Get("name").(string)
	if newToken.Name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	tokens := []totpEntry{}

	for _, token := range user.TOTPTokens {
		if token.Name != newToken.Name {
			tokens = append(user.TOTPTokens, token)
		}
	}

	pin := d.Get("pin").(string)
	if pin == "" {
		return logical.ErrorResponse("missing pin"), nil
	}

	newToken.PinHash, err = bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		AccountName: username,
		Issuer:      "Vault",
	})
	if err != nil {
		return nil, err
	}

	newToken.Secret = key.Secret()

	tokens = append(tokens, newToken)
	user.TOTPTokens = tokens

	entry, err := logical.StorageEntryJSON(userPrefix+username, user)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"totp_secret": newToken.Secret,
		},
	}, nil
}

func (b *backend) pathTOTPDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := d.Get("username").(string)
	if username == "" {
		return logical.ErrorResponse("missing username"), nil
	}

	user, err := b.getUser(ctx, req.Storage, username)
	if err != nil {
		return nil, err
	}

	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	if user == nil {
		return logical.ErrorResponse("username not found"), nil
	}

	tokens := []totpEntry{}

	for _, token := range user.TOTPTokens {
		if token.Name != name {
			tokens = append(tokens, token)
		}
	}

	user.TOTPTokens = tokens

	entry, err := logical.StorageEntryJSON(userPrefix+username, user)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
