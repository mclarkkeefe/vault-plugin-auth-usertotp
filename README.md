# User TOTP Auth Method for Vault

`vault-plugin-auth-usertotp` is an auth method plugin for HashiCorp Vault.  Create user accounts, add TOTP tokens (user supplied pin + totp), and have peace of mind using 2FA.

This plugin is also a drop-in replacement for the native `userpass` auth method, so stop using that and use this instead!

## Install

Assuming you have an already running/configured Vault instance:

1. Add `plugin_directory = "<folder-where-you-will-put-the plugin>"` to your vault config
2. Download the plugin from the releases page to the folder above
3. Register the plugin in vault: `vault plugin register -sha256=$(sha256sum <path/to/plugin> | cut -d\  -f 1)) <plugin-name>`
4. Enable the plugin in vault: `vault auth enable -path=userpass <plugin-name>`

## Use

After installing the plugin:

### Create Users

1. `vault write auth/userpass/users/<username> token_policies="<list-of-policies-for-user>"`

### Create User TOTP Tokens

1. `vault write auth/userpass/users/<username>/totp name=<name-of-token> pin=<pin/password-for-token>`
2. The command will return a `totp_secret` value, this is the value you should add to your Google Authenticator.  Alternatively, you can generate a QR code: `qrencode -t ANSI256 -o - $(echo otpauth://totp/Vault%20(<username>)?secret=<totp_secret>&issuer=Vault)`

### Delete Users

1. `vault delete auth/userpass/users/<username>`

### Delete User TOTP Tokens

1. `vault delete auth/userpass/users/<username>/totpname=<totp-token-name>`

### List Users

1. `vault list auth/userpass/users`

### Read User (including TOTP Token names)

1. `vault read auth/userpass/users/<username>`
2. Any TOTP tokens for the user will be listed under totp_token_names.

## Build

Run `make build`
