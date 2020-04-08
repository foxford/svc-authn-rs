# Authn

[![Build Status][travis-img]][travis]

An authentication library.



## License

The source code is provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[travis]:https://travis-ci.com/netology-group/svc-authn-rs?branch=master
[travis-img]:https://travis-ci.com/netology-group/svc-authn-rs.png?branch=master


## CLI

This tool provides three operations on json web tokens: token [generation](#token-generation), [decoding](#token-decoding), and [verification](#token-verification)


### Token generation
Generates a token for given account with expiration timestamp provided via parameter or via [config](#config).

For example to get a valid for an hour token for account `bar` at `baz.services`:
```bash
$ svc-authn-cli sign --account bar.baz.services --expires_in 3600
REJ0eXAiOiJKV...
```

Available params:
- `--expires-in seconds | --expires-at datetime` - sets token encryption either `seconds` into the future or at `datetime` moment in time (available formats are "YYYY-MM-DD" and "YYYY-MM-DD hh:mm:ss")
- `--cross-audience` - scope for audience
- `--account | -a` - account to issue token for, required parameter


### Config
Config file is supplied via `--config | -c` parameter or read by default from `~/.svc/authn-cli.toml`.

It provides default `expires_in` value for token (when no `--expires-in | --expires-at` parameter was given to `sign`) and a list of audiences with corresponding issuer, encoding algorithm and keys to sign and verify tokens.

Have a look at the [sample](sample_conf/authn-cli.toml.example) config.



### Token decoding
Given a token we can extract its content:
```bash
$ svc-authn-cli decode REJ0eXAiOiJKV...
{ "iss" : "baz.services", "aud" : "baz.services", "sub" : "bar", "exp": 1586531265 }
```

### Token verification
Given a token we can verify its signature:
```bash
$ svc-authn-cli verify REJ0eXAiOiJKV...
Verification passed, token valid for 3543 seconds
```

