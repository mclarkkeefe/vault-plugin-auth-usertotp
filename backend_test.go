package main

import (
	"context"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pquerna/otp/totp"
)

var b logical.Backend
var ctx context.Context
var storage *logical.InmemStorage

func TestMain(m *testing.M) {
	var err error

	storage = &logical.InmemStorage{}

	config := logical.TestBackendConfig()
	config.StorageView = storage

	ctx = context.Background()

	b, err = Factory(ctx, config)
	if err != nil {
		log.Fatal("failed to create backend:", err)
	}

	if b == nil {
		log.Fatal("failed to create backend: ", err)
	}

	r := m.Run()

	os.Exit(r)
}

func TestTOTPLogin(t *testing.T) {
	// pathTokenCreate
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser",
		Operation: logical.CreateOperation,
		Storage:   storage,
		Data:      map[string]interface{}{},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser/totp",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"name": "test",
			"pin":  "test",
		},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["totp_secret"] == nil {
		t.Fatalf("bad: no totp_secret returned")
	}

	secret := resp.Data["totp_secret"].(string)
	code, _ := totp.GenerateCode(secret, time.Now())

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "login/totpuser",
		Operation: logical.UpdateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"password": "test" + code,
		},
	})

	if err != nil || resp == nil || resp != nil && resp.Auth == nil {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser",
		Operation: logical.ReadOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["totp_token_names"].([]string)[0] != "test" {
		t.Fatalf("bad: token list incorrect")
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser",
		Operation: logical.ReadOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["totp_token_names"].([]string)[0] != "test" {
		t.Fatalf("bad: token list incorrect")
	}

	_, _ = b.HandleRequest(ctx, &logical.Request{
		Data: map[string]interface{}{
			"name": "test",
		},
		Path:      "users/totpuser/totp",
		Operation: logical.DeleteOperation,
		Storage:   storage,
	})

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser",
		Operation: logical.ReadOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if len(resp.Data["totp_token_names"].([]string)) != 0 {
		t.Fatalf("bad: token delete failed")
	}

	_, _ = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/totpuser",
		Operation: logical.DeleteOperation,
		Storage:   storage,
	})

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users",
		Operation: logical.ListOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["keys"] != nil {
		t.Fatalf("bad: user token delete failed")
	}
}

func TestUsers(t *testing.T) {
	// pathUserWrite
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Path:      "users/testuser",
		Operation: logical.CreateOperation,
		Storage:   storage,
		Data: map[string]interface{}{
			"token_ttl":      5,
			"token_max_ttl":  10,
			"token_policies": []string{"foo"},
		},
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}

	// pathUserRead
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/testuser",
		Operation: logical.ReadOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["token_ttl"].(int64) != 5 && resp.Data["token_max_ttl"].(int64) != 10 {
		t.Fatalf("bad: token_ttl and token_max_ttl are not set correctly")
	}
	if !reflect.DeepEqual(resp.Data["token_policies"], []string{"foo"}) {
		t.Fatal("bad: token policies don't match")
	}

	//pathUsersList
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users",
		Operation: logical.ListOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["keys"].([]string)[0] != "testuser" {
		t.Fatalf("bad: user list incorrect")
	}

	// pathUserDelete
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users/testuser",
		Operation: logical.DeleteOperation,
		Storage:   storage,
	})

	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Path:      "users",
		Operation: logical.ListOperation,
		Storage:   storage,
	})

	if err != nil || (resp == nil || resp != nil && resp.IsError()) {
		t.Fatalf("bad: resp: %#v\nerr: %v\n", resp, err)
	}
	if resp.Data["keys"] != nil {
		t.Fatalf("bad: user delete failed")
	}
}
