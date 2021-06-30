package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type userEntry struct {
	tokenutil.TokenParams

	TOTPTokens     []totpEntry `json:"totp_tokens"`
	TOTPTokenNames []string    `json:"totp_token_names"`
}

func pathUsers(b *backend) *framework.Path {
	return &framework.Path{
		DisplayAttrs: &framework.DisplayAttributes{
			Navigation: true,
			ItemType:   "User",
		},
		HelpDescription: "",
		HelpSynopsis:    "",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathUsersList,
			},
		},
		Pattern: userPrefix + "?",
	}
}

func pathUsersUsername(b *backend) *framework.Path {
	p := &framework.Path{
		DisplayAttrs: &framework.DisplayAttributes{
			Action:   "Create",
			ItemType: "User",
		},
		ExistenceCheck:  b.userExistenceCheck,
		HelpDescription: "",
		HelpSynopsis:    "",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathUserDelete,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathUserRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUserWrite,
			},
		},
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeLowerCaseString,
				Description: "Username for this user.",
			},
			"totp_token_names": {
				Type:        framework.TypeStringSlice,
				Description: "List of TOTP tokens for a user.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},
		Pattern: userPrefix + framework.GenericNameRegex("username"),
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) getUser(ctx context.Context, s logical.Storage, name string) (*userEntry, error) {
	raw, err := s.Get(ctx, userPrefix+name)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	user := new(userEntry)
	if err := raw.DecodeJSON(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (b *backend) pathUserDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user := userPrefix + d.Get("username").(string)
	tokens, err := req.Storage.List(ctx, user+totpPrefix)
	if err != nil {
		return nil, err
	}

	if len(tokens) > 0 {
		for _, token := range tokens {
			err = req.Storage.Delete(ctx, user+totpPrefix+token)
			if err != nil {
				return nil, err
			}
		}
	}

	err = req.Storage.Delete(ctx, userPrefix+d.Get("username").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathUserRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	user, err := b.getUser(ctx, req.Storage, d.Get("username").(string))
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, nil
	}

	if len(user.TOTPTokens) > 0 {
		for _, token := range user.TOTPTokens {
			user.TOTPTokenNames = append(user.TOTPTokenNames, token.Name)
		}
	}

	data := map[string]interface{}{}
	user.PopulateTokenData(data)

	data["totp_token_names"] = user.TOTPTokenNames

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathUserWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("username").(string)
	user, err := b.getUser(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if user == nil {
		user = &userEntry{}
	}

	if err := user.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	entry, err := logical.StorageEntryJSON(userPrefix+name, user)
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathUsersList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	users, err := req.Storage.List(ctx, userPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(users), nil
}

func (b *backend) userExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	userEntry, err := b.getUser(ctx, req.Storage, d.Get("username").(string))
	if err != nil {
		return false, err
	}

	return userEntry != nil, nil
}
