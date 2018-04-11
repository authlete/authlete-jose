jose-generator
==============


Overview
--------

`jose-generator` is a command line tool to generate JOSE (JavaScript Object
Signing and Encryption) in the compact serialization format. For maximum
usability, this tool provides various ways to specify payload data, algorithms
and keys.


Note
----

This tool is under development. Encryption is not supported yet.


Preparation
-----------

```
$ git clone https://github.com/authlete/authlete-jose
$ cd authlete-jose
$ mvn compile
$ . bin/jose-generator-completion
```

`jose-generator-completion` contains a call of the `complete` command (a builtin
command of `bash`) which sets up argument completion for the `jose-generator`
command. After the setup, command line options of `jose-generator` are properly
completed when you type a tab at the command prompt after typing `jose-generator`.
See [Programmable Completion Builtins][3] for details about the `complete` command.


Basics
------

| Category | Description |
|:--|:--|
| Payload | Use one of the `--payload[-*]` options to specify payload data. If none of the options is used, the standard input is read as the source of the payload data. |
| Signing | Use the `--sign` option to perform signing. |
| Signing key | There are several ways to specify a key for signing. Details are described later. |
| Signing algorithm | Use the `--signing-alg` option, or embed the `alg` parameter in the JWK. |
| Encrypting | Use the `--encrypt` option to perform encrypting. |
| Encrypting key | There are several ways to specify a key for encrypting. Details are described later. |
| Encrypting algorithm | Use the `--encrypting-alg` option and `--encrypting-enc` option, or embed the `alg` parameter in the JWKs. |
| Output | The output is written into the standard output unless the `--output-file` option is given. |

If neither the `--sign` option nor the `--encrypt` option is given, an unsecured
JWS is generated. If both options are given, a nested JOSE is generated. By default,
the nesting order is _sign and then encrypt_, which is the same order required by
the specification of ID Token. This order can be reversed by the `--encrypt-then-sign`
option.


Command Line Options
--------------------

```
./bin/jose-generator
  [--sign | -s]
  [--encrypt | -e]
  [--encrypt-then-sign]

  [--payload {PAYLOAD} | -p {PAYLOAD}]
  [--payload-base64url {BASE64URL}]
  [--payload-file {FILE}]
  [--payload-uri {URI}]

  [--jwk-signing-alg {JWK}]
  [--jwk-signing-alg-file {FILE}]
  [--jwk-signing-alg-uri {URI}]

  [--jwk-encrypting-alg {JWK}]
  [--jwk-encrypting-alg-file {FILE}]
  [--jwk-encrypting-alg-uri {URI}]

  [--jwk-encrypting-enc {JWK}]
  [--jwk-encrypting-enc-file {FILE}]
  [--jwk-encrypting-enc-uri {URI}]

  [--jwks {JWKSet}]
  [--jwks-file {FILE}]
  [--jwks-uri {URI}]

  [--jwks-signing {JWKSet}]
  [--jwks-signing-file {FILE}]
  [--jwks-signing-uri {URI}]

  [--jwks-signing-alg {JWKSet}]
  [--jwks-signing-alg-file {FILE}]
  [--jwks-signing-alg-uri {URI}]

  [--jwks-encrypting {JWKSet}]
  [--jwks-encrypting-file {FILE}]
  [--jwks-encrypting-uri {URI}]

  [--jwks-encrypting-alg {JWKSet}]
  [--jwks-encrypting-alg-file {FILE}]
  [--jwks-encrypting-alg-uri {URI}]

  [--jwks-encrypting-enc {JWKSet}]
  [--jwks-encrypting-enc-file {FILE}]
  [--jwks-encrypting-enc-uri {URI}]

  [--signing-alg {ALG}]
  [--signing-alg-kid {KID}]

  [--signing-alg-key {KEY}]
  [--signing-alg-key-base64url {BASE64URL}]
  [--signing-alg-key-file {FILE}]
  [--signing-alg-key-uri {URI}]

  [--jws-header {JWSHeader}]
  [--jws-header-base64url {BASE64URL}]
  [--jws-header-file {FILE}]
  [--jws-header-uri {URI}]

  [--encrypting-alg {ALG}]
  [--encrypting-alg-kid {KID}]

  [--encrypting-enc {ENC}]
  [--encrypting-enc-kid {KID}]

  [--connect-timeout {TIMEOUT}]
  [--read-timeout {TIMEOUT}]

  [--output-file {FILE} | -o {FILE}]

  [--verbose | -v]
```

First, as mentioned in _Preparation_ section above, it is recommended to source
`bin/jose-generator-completion` so that argument completion can work.

```
$ . bin/jose-generator-completion
```

| Option | Description |
|:--|:--|
| `--sign` | Performs signing. |
| `-s` | Alias of `--sign`. |
| `--encrypt` | Performs encrypting. |
| `-e` | Alias of `--encrypt`. |
| `--encrypt-then-sign` | When both signing and encrypting are performed, by default, signing is performed first. If you want to reverse this order, use this option. |
| `--payload` _PAYLOAD_ | Specifies the value of payload data. |
| `-p` _PAYLOAD_ | Alias of `--payload`. |
| `--payload-base64url` _BASE64URL_ | Specifies the value of payload data in the base64url format. |
| `--payload-file` _FILE_ | Specifies the file which contains payload data. |
| `--payload-uri` _URI_ | Specifies the URI which points to payload. |
| `--jwk-signing-alg` _JWK_ | Specifies a JWK which represents a key for signing. |
| `--jwk-signing-alg-file` _FILE_ | Specifies the file which contains a JWK which contains a key for signing. |
| `--jwk-signing-alg-uri` _URI_ | Specifies the URI which points to a JWK which contains a key for signing. |
| `--jwk-encrypting-alg` _JWK_ | Specifies a JWK which represents a key for encrypting (for `alg` in JWE header). |
| `--jwk-encrypting-alg-file` _FILE_ | Specifies the file which contains a JWK which represents a key for encrypting (for `alg` in JWE header). |
| `--jwk-encrypting-alg-uri` _URI_ | Specifies the URI which points to a JWK which represents a key for encrypting (for `alg` in JWE header). |
| `--jwk-encrypting-enc` _JWK_ | Specifies a JWK which represents a key for encrypting (for `enc` in JWE header). |
| `--jwk-encrypting-enc-file` _FILE_ | Specifies the file which contains a JWK which represents a key for encrypting (for `enc` in JWE header). |
| `--jwk-encrypting-enc-uri` _URI_ | Specifies the URI which points to a JWK which represents a key for encrypting (for `enc` in JWE header). |
| `--jwks` _JWKSet_ | Specifies a JWK Set document which contains keys for signing and encrypting. |
| `--jwks-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for signing and encrypting. |
| `--jwks-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for signing and encrypting. |
| `--jwks-signing` _JWKSet_ | Specifies a JWK Set document which contains keys for signing. |
| `--jwks-signing-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for signing. |
| `--jwks-signing-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for signing. |
| `--jwks-signing-alg` _JWKSet_ | Specifies a JWK Set document which contains keys for signing (for `alg` in JWS header). |
| `--jwks-signing-alg-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for signing (for `alg` in JWS header). |
| `--jwks-signing-alg-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for signing (for `alg` in JWS header). |
| `--jwks-encrypting` _JWKSet_ | Specifies a JWK Set document which contains keys for encrypting. |
| `--jwks-encrypting-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for encrypting. |
| `--jwks-encrypting-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for encrypting. |
| `--jwks-encrypting-alg` _JWKSet_ | Specifies the JWK Set document which contains keys for encrypting (for `alg` in JWE header). |
| `--jwks-encrypting-alg-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for encrypting (for `alg` in JWE header). |
| `--jwks-encrypting-alg-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for encrypting (for `alg` in JWE header). |
| `--jwks-encrypting-enc` _JWKSet_ | Specifies a JWK Set document which contains keys for encrypting (for `enc` in JWE header). |
| `--jwks-encrypting-enc-file` _FILE_ | Specifies the file which contains a JWK Set document which contains keys for encrypting (for `enc` in JWE header). |
| `--jwks-encrypting-enc-uri` _URI_ | Specifies the URI which points to a JWK Set document which contains keys for encrypting (for `enc` in JWE header). |
| `--signing-alg` _ALG_ | Specifies an algorithm for signing. Supported values are `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512` and `none`. |
| `--signing-alg-kid` _KID_ | Specifies the key ID of a JWK which represents a key for signing. If given, the key ID is used to find a proper JWK in a JWK Set document. |
| `--signing-alg-key` _KEY_ | Specifies a key for signing. This option works only when the signing algorithm is symmetric (`HS256`, `HS384` or `HS512`). |
| `--signing-alg-key-base64url` _BASE64URL_ | Specifies the base64url representation of a key for signing. This option works only when the signing algorithm is symmetric (`HS256`, `HS384` or `HS512`). |
| `--signing-alg-key-file` _FILE_ | Specifies the file which contains a key for signing. This option works only when the signing algorithm is symmetric (`HS256`, `HS384` or `HS512`). |
| `--signing-alg-key-uri` _URI_ | Specifies the URI which points to a key for signing. This option works only when the signing algorithm is symmetric (`HS256`, `HS384` or `HS512`). |
| `--jws-header` _JWSHeader_ | Specifies a JWS header. |
| `--jws-header-base64url` _BASE64URL_ | Specifies the base64url representation of a JWS header. |
| `--jws-header-file` _FILE_ | Specifies the file which contains a JWS header. |
| `--jws-header-uri` _URI_ | Specifies the URI which points to a JWS header. |
| `--encrypting-alg` _ALG_ | Specifies an algorithm for encrypting (for `alg` in JWE header). Supported values are `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `A128KW`, `A192KW` `A256KW`, `dir`, `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`, `A128GCMKW`, `A192GCMKW`, `A256GCMKW`, `PBES2-HS256+A128KW`, `PBES2-H384+A192KW` and `PBES2-HS512+A256KW`. |
| `--encrypting-alg-kid` _KID_ | Specifies the key ID of a JWK which represents a key for encrypting (for `alg` in JWE header). If given, the key ID is used to find a proper JWK in a JWK Set document. |
| `--encrypting-enc` _ENC_ | Specifies an algorithm for encrypting (for `enc` in JWE header). Supported values are `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A192GCM` and `A256GCM`. |
| `--encrypting-enc-kid` _KID_ | Specifies the key ID of a JWK which represents a key for encrypting (for `enc` in JWE header). If given, the key ID is used to find a proper JWK in a JWK Set document. |
| `--connect-timeout` _TIMEOUT_ | Connection timeout in milliseconds on fetching a JWK Set document. |
| `--read-timeout` _TIMEOUT_ | Read timeout in milliseconds on fetching a JWK Set document. |
| `--output-file` _FILE_ | The file to which the output is written into. |
| `-o` _FILE_ | Alias of `--output-file`. |
| `--verbose` | Verbose reporting. |
| `-v` | Alias of `--verbose`. |


Usage
-----

### Unsecured JWS

The following is the simplest example.

```
$ ./bin/jose-generator --payload hello
eyJhbGciOiJub25lIn0.aGVsbG8.
```

The above command generates an *unsecured JWS* which has `hello` as its payload
data. Signing and encrypting are nor performed because the `--sign` option and
the `--encrypt` option are not given. See [A.5. Example Unsecured JWS][2] in
[RFC 7515][1] (JSON Web Signature (JWS)) for details about unsecured JWS.

Even if the `--sign` option is given, if `none` is specified as the signing
algorithm (by using the `--signing-alg` option), an unsecured JWS is generated.

```
$ ./bin/jose-generator --payload hello --sign --signing-alg none
eyJhbGciOiJub25lIn0.aGVsbG8.
```


### Payload

The examples above used the `--payload` option to specify the value of payload
data. The `-p` option is an alias of `--payload`.

```
$ ./bin/jose-generator -p hello
eyJhbGciOiJub25lIn0.aGVsbG8.
```

When you give JSON to the `--payload` (or `-p`) option, wrap the JSON with
`\''` and `'\'` instead of `'` and `'`. This is needed as a workaround for
multiple-time shell escape.

```
$ ./bin/jose-generator --payload \''{"hello":"world"}'\'
eyJhbGciOiJub25lIn0.eyJoZWxsbyI6IndvcmxkIn0.
```

If `'{JSON}'` is not wrapped with `\'` and `\'`,

```
$ ./bin/jose-generator --payload '{"hello":"world"}'
eyJhbGciOiJub25lIn0.e2hlbGxvOndvcmxkfQ.
```

you will get an unexpected result (double quotation marks in the JSON are removed).

```
$ npm install -g base64-url-cli
$ base64url decode e2hlbGxvOndvcmxkfQ
{hello:world}
```

When payload data is binary, the `--payload-base64url` option can be used.
This option accepts the base64url representation of payload data.

```
$ ./bin/jose-generator --payload-base64url aGVsbG8
eyJhbGciOiJub25lIn0.aGVsbG8.
```

If payload data is stored in a file, the `--payload-file` option can be used.

```
$ echo -n hello > payload-hello.dat
$ ./bin/jose-generator --payload-file payload-hello.dat
eyJhbGciOiJub25lIn0.aGVsbG8.
```

If payload data is hosted on a web server, the `--payload-uri` option can be used.

```
$ php -S 0.0.0.0:8080 &
$ ./bin/jose-generator --payload-uri http://localhost:8080/payload-hello.dat
eyJhbGciOiJub25lIn0.aGVsbG8.
```

A local file can be referred to by using `file:` scheme.

```
$ ./bin/jose-generator --payload-uri file:payload-hello.dat
eyJhbGciOiJub25lIn0.aGVsbG8.
```

If none of the `--payload[-*]` options is given, the standard input is read as
the source of payload data.

```
$ echo -n hello | ./bin/jose-generator
eyJhbGciOiJub25lIn0.aGVsbG8.
```

In summary, payload data is looked up in the following order.

1. `--payload` (`-p`)
2. `--payload-base64url`
3. `--payload-file`
4. `--payload-uri`
5. The standard input


### Output

By default, the output is written into the standard output. You can make
`jose-generator` write the output into a file by using the `--output-file`
option.

```
$ ./bin/jose-generator -p hello --output-file hello.out
```

The `-o` option is an alias of `--output-file`.

```
$ ./bin/jose-generator -p hello -o hello.out
```


### Signing

*For signing, the `--sign` option is needed.* Even if other options related to
signing (e.g. the `--signing-alg` option) are given, signing is not performed
if the `--sign` option is not given. The `-s` option can be used as an alias of
the `--sign` option.

For signing, (1) an *algorithm* and (2) a *key* need to be specified in some way
or other. The most intuitive way to specify an algorithm for signing is to use
the `--signing-alg` option as follows.

```
--signing-alg HS256
```

Supported algorithms are listed in the table below. See
[3.1. "alg" (Algorithm) Header Parameter Values for JWS][5] in [RFC 7518][4]
(JSON Web Algorithms (JWA)) for details.

| `alg` | Algorithm |
|:-:|:--|
| `HS256` | HMAC using SHA-256 |
| `HS384` | HMAC using SHA-384 |
| `HS512` | HMAC using SHA-512 |
| `RS256` | RSASSA-PKCS1-v1_5 using SHA-256 |
| `RS384` | RSASSA-PKCS1-v1_5 using SHA-384 |
| `RS512` | RSASSA-PKCS1-v1_5 using SHA-512 |
| `ES256` | ECDSA using P-256 and SHA-256 |
| `ES384` | ECDSA using P-384 and SHA-384 |
| `ES512` | ECDSA using P-521 and SHA-512 |
| `PS256` | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |
| `PS384` | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |
| `PS512` | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |
| `none`  | No digital signature or MAC performed |


#### JWK for Signing Key

There are several ways to specify a key for signing. A generic way is to give a
[JWK][8] by using one of the `--jwk-signing-alg[-*]` options.

```
$ ./bin/jose-generator -p hello --sign --signing-alg HS256 \
  --jwk-signing-alg \''{"kty":"oct","k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"}'\'
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

The example above uses `HS256` as an algorithm for signing and
`abcdefghijklmnopqrstuvwxyz012345` as a shared key
(`YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU` is the base64url representation of
`abcdefghijklmnopqrstuvwxyz012345`).

On the command line in the example above, the JWK is wrapped with `\''` and `'\'`
(not with `'` and `'`). This is needed as a workaround for multiple-time shell
escape as required for the `--payload` option.

A cleaner way to specify a JWK is to prepare a JWK as a file and pass the path of
the file by the `--jwk-signing-alg-file` option.

```
$ cat oct.jwk
{
  "kty":"oct",
  "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
}
```

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --jwk-signing-alg-file oct.jwk
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the JWK file is hosted on a web server, the `--jwk-signing-alg-uri` option can
be used.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --jwk-signing-alg-uri http://localhost:8080/oct.jwk
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the JWK contains `alg`, the `--signing-alg` option can be omitted.

```
$ cat oct.jwk
{
  "kty":"oct",
  "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU",
  "alg":"HS256"
}
```

```
$ ./bin/jose-generator -p hello -s --jwk-signing-alg-file oct.jwk
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the JWK contains `kid`, the JWS header of the output will have the `kid`
parameter.

```
$ cat oct.jwk
{
  "kty":"oct",
  "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU",
  "alg":"HS256",
  "kid":"123"
}
```

```
$ ./bin/jose-generator -p hello -s --jwk-signing-alg-file oct.jwk
eyJraWQiOiIxMjMiLCJhbGciOiJIUzI1NiJ9.aGVsbG8.z41OFTgrmWqcH0dwnnJBRIo3KTSdpTtYSsvGCjyHQio
```

```
$ base64url decode eyJraWQiOiIxMjMiLCJhbGciOiJIUzI1NiJ9
{"kid":"123","alg":"HS256"}
```

The following is an example of `ES256`.

```
$ cat ec.jwk
{
  "kty":"EC",
  "crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
}
```

```
$ ./bin/jose-generator -p hello -s --signing-alg ES256 \
  --jwk-signing-alg-file ec.jwk
eyJhbGciOiJFUzI1NiJ9.aGVsbG8.rfdxb1WbyrjpzUx0EEviMK0QQvKQAX-xkzNRIqaTo1VREUC7dnvBmjJImIbkPuws6Rr9WEH2L28lQKFxFGun-Q
```

Note that `ES*` algorithms generate a different signature every time.

```
$ ./bin/jose-generator -p hello -s --signing-alg ES256 \
  --jwk-signing-alg-file ec.jwk
eyJhbGciOiJFUzI1NiJ9.aGVsbG8.4xEpJh357IsNjO1PQ26VtHoC15_GdQnW0vQmdjowM9gLsqEi4Loib9ny9ovY26uAw3DWFlnu0xjwHifAgv8rIw
```

An `RS256` example is here:

```
$ cat rsa.jwk
{
  "kty":"RSA",
  "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
  "e":"AQAB",
  "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
  "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
  "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
  "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
  "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
  "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
}
```

```
$ ./bin/jose-generator -p hello -s --signing-alg RS256 \
  --jwk-signing-alg-file rsa.jwk
eyJhbGciOiJSUzI1NiJ9.aGVsbG8.KMS_io4NPrTJFIzudgqJ-6wx9wpVjNqSbySzEvYzZ8SAViwH8QWs9GvQvbl4rAyaH_LYuPRll4Z2zKzSL1a5YWtq2EtesuB9WYf0TP3X9V0gylMpu1GavC77TvRGZXNaUSZQRZTsnBabZPA4xaRsMq-LOqx4i78f-OChTEa1DFAf6incDVta2Xd7v5qaMLXK1hdS9Iwoj2Y_54rS6rGHhWIU7xQ9TBWHGo0GFtE3CHijARY7G_jdO2MBHqLleTIYSE7wOyouxlXzPE_5rmDEhcNJWzKyhZzWIzFX_cDzDN8yQ6mtieJVcXqz9YBW0bAHcFyPcQjrOh6bxUrmT1Sa1w
```


#### Signing Key for Symmetric Algorithm

If a symmetric algorithm (`HS256`, `HS384` or `HS512`) is used, a shared key
can be specified in easier ways. The following example specifies a shared key
by the `--signing-alg-key` option.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --signing-alg-key abcdefghijklmnopqrstuvwxyz012345
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the shared key is binary data, the `--signing-alg-key-base64url` option can
be used. This option accepts the base64url representation of a shared key.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --signing-alg-key-base64url YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the shared key is stored in a file, the `--signing-alg-key-file` option can
be used.

```
$ echo -n abcdefghijklmnopqrstuvwxyz012345 > key.txt
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --signing-alg-key-file key.txt
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If the shared key is hosted on a web server, the `--signing-alg-key-uri` option
can be used.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --signing-alg-key-uri http://localhost:8080/key.txt
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```


#### JWS Header

`jose-generator` generates a JWS header as necessary, but you can specify a
JWS header by using one of the `--jws-header[-*]` options.

In the following example, `{"alg":"HS256"}` is specified as a JWS header by
using the `--jws-header` option. Because the signing algorithm is written in
the JWS header, the `--signing-alg` option can be omitted in this case.
Note again that the JSON (JWS header) on the command line is wrapped with
`\''` and `'\'`.

```
$ ./bin/jose-generator -p hello -s \
  --signing-alg-key abcdefghijklmnopqrstuvwxyz012345 \
  --jws-header \''{"alg":"HS256"}'\'
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

When you want to pass the value of a JWS header in the base64url format,
the `--jws-header-base64url` option can be used.

```
$ ./bin/jose-generator -p hello -s \
  --signing-alg-key abcdefghijklmnopqrstuvwxyz012345 \
  --jws-header-base64url eyJhbGciOiJIUzI1NiJ9
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If you want to use a JWS header which is stored in a file, you can use the
`--jws-header-file` option.

```
$ echo '{"alg":"HS256"}' > jws-header.json
$ ./bin/jose-generator -p hello -s \
  --signing-alg-key abcdefghijklmnopqrstuvwxyz012345 \
  --jws-header-file jws-header.json
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

If a JWS header is hosted on a web server, the `--jws-header-uri` option can be used.

```
$ ./bin/jose-generator -p hello -s \
  --signing-alg-key abcdefghijklmnopqrstuvwxyz012345 \
  --jws-header-uri http://localhost:8080/jws-header.json
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```


#### JWK Set for Signing Key

A JWK Set document can be used as a source of a signing key. To pass a JWK
Set document which contains a signing key, the `--jwks-signing-alg` opiton
can be used.

```
--jwks-signing-alg \''{"keys":[{"kty":"oct","k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"}]}'\'
```

If the JWK Set document is stored in a file, the `--jwks-signing-alg-file` option
can be used.

```
$ cat signing-alg.jwks
{
  "keys":[
    {
      "kty":"oct",
      "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
    }
  ]
}
```

```
--jwks-signing-alg-file signing-alg.jwks
```

If the JWK Set document is hosted on a web server, the `--jwks-signing-alg-file`
option can be used.

```
--jwks-signing-alg-uri http://localhost:8080/signing-alg.jwks
```

A JWK Set document may contain multiple keys. `jose-generator` uses the following
steps to select a proper JWK from a JWK Set document.

1. If the number of JWKs contained in the JWK Set document is 1, the JWK is selected.
2. If the `--signing-alg-kid` option is given, the specified key ID is used to find a JWK.
3. If there exists a JWK whose `alg` matches the signing algorithm, the JWK is used. If there exist multiple candidates, a JWK which has the `kid` parameter is preferred to other JWKs.
4. If the signing algorithm is not specified, but if all the JWKs in the JWK Set document have the `alg` parameter and their values are identical, it is used as the algorithm for signing. One JWK will be selected from among the JWKs. A JWK having the `kid` parameter is preferred to other JWKs.
5. A JWK having a proper key type (`kty`) for the algorithm for signing is selected. A JWK having the `kid` parameter is preferred to other JWKs.
6. `jose-generator` fails if the above steps do not find a proper JWK.

Examples are below.

*Example-1:* If the number of JWKs contained in a JWK Set document is 1,

```
$ cat signing-alg-1.jwks
{
  "keys":[
    {
      "kty":"oct",
      "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
    }
  ]
}
```

the JWK is used for signing.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --jwks-signing-alg-file signing-alg-1.jwks
eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ
```

*Example-2:* If a JWK Set document contains multiple JWKs,

```
$ cat signing-alg-2.jwks
{
  "keys":[
    {
      "kty":"oct",
      "k":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2NTQ",
      "kid":"ABC654"
    },
    {
      "kty":"oct",
      "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU",
      "kid":"abc345"
    },
    {
      "kty":"oct",
      "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5QUJDREVGR0hJSktM",
      "alg":"HS384"
    }
  ]
}
```

the `--signing-alg-kid` option can be used to determine the JWK for signing.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --jwks-signing-alg-file signing-alg-2.jwks \
  --signing-alg-kid abc345
eyJraWQiOiJhYmMzNDUiLCJhbGciOiJIUzI1NiJ9.aGVsbG8.TxS34rK-BKDtaNmxXMxIOFz99MUrVBQYB5bf7tZT_nM
```

```
$ base64url decode eyJraWQiOiJhYmMzNDUiLCJhbGciOiJIUzI1NiJ9
{"kid":"abc345","alg":"HS256"}
```

*Example-3:* If there exists a JWK having the `alg` parameter and its value
matches the algorithm for signing, the JWK is used.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS384 \
  --jwks-signing-alg-file signing-alg-2.jwks
eyJhbGciOiJIUzM4NCJ9.aGVsbG8.WTkQfR2-KZa6bzEJtsaMTYSqMlSu7FOtK2gHPlxtTEWvdhCYAWVSq-yC2iLwvV3H
```

```
$ base64url decode eyJhbGciOiJIUzM4NCJ9
{"alg":"HS384"}
```

*Example-4:* Even if the `--signing-alg` is missing, if all the JWKs have the
`alg` parameter and their values are identical,

```
$ cat signing-alg-3.jwks
{
  "keys":[
    {
      "kty":"oct",
      "k":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo5ODc2NTQ",
      "alg":"HS256"
    },
    {
      "kty":"oct",
      "k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU",
      "alg":"HS256",
      "kid":"abc345"
    }
  ]
}
```

the value of the `alg` parameter is used as an algorithm for signing.

```
$ ./bin/jose-generator -p hello -s \
  --jwks-signing-alg-file signing-alg-3.jwks
eyJraWQiOiJhYmMzNDUiLCJhbGciOiJIUzI1NiJ9.aGVsbG8.TxS34rK-BKDtaNmxXMxIOFz99MUrVBQYB5bf7tZT_nM
```

A JWK which has the `kid` parameter is preferred to other JWKs.

```
$ base64url decode eyJraWQiOiJhYmMzNDUiLCJhbGciOiJIUzI1NiJ9
{"kid":"abc345","alg":"HS256"}
```

*Example-5:* A JWK which has a proper key type (`kty`) for the signing algorithm is selected.

```
$ ./bin/jose-generator -p hello -s --signing-alg HS256 \
  --jwks-signing-alg-file signing-alg-2.jwks
eyJraWQiOiJBQkM2NTQiLCJhbGciOiJIUzI1NiJ9.aGVsbG8.vF13uwnSPOH_rhZfDKBqREDE34rlGtPzQ6vE9Z1cPlI
```

```
$ base64url decode eyJraWQiOiJBQkM2NTQiLCJhbGciOiJIUzI1NiJ9
{"kid":"ABC654","alg":"HS256"}
```


#### --jwks[-*] Options for Signing

If none of the `--jwk-signing-alg[-*]` options (and `--signing-alg-key[-*]` options
for symmetric algorithms) is given, `jose-generator` will try to get a JWK Set
document for a key for signing.

First, `jose-generator` checks if one of the following options is used.

- `--jwks-signing-alg`
- `--jwks-signing-alg-file`
- `--jwks-signing-alg-uri`

If none of the above is used, `jose-generator` checks the following set.

- `--jwks-signing`
- `--jwks-signing-file`
- `--jwks-signing-uri`

There is no practical difference between `jwks-signing-alg[-*]` options and
`jwks-signing[-*]` options, though.

If none of the above is used, `jose-generator` checks the following set.

- `--jwks`
- `--jwks-file`
- `--jwks-uri`

In addition to keys for signing, a JWK Set document specified by `--jwks`,
`--jwks-file` or `--jwks-uri` options may contain keys for encrypting.
In other words, a JWK Set document specified by `--jwks`, `--jwks-file` or
`--jwks-uri` options may be referred to during encryption process, too.


### Encrypting

Under development.


As a Library
------------

```java
// Command line options.
String[] args = new String[] {
    "--payload", "hello",
    "--sign",
    "--signing-alg", "HS256",
    "--signing-alg-key", "abcdefghijklmnopqrstuvwxyz012345"
};

// Generate a JWS.
String jws = new JoseGenerator().execute(args);

// 'jws' holds "eyJhbGciOiJIUzI1NiJ9.aGVsbG8.U8o-wv2ZGFwSVNTFd1jIY2c8WJMPwgKriEnXUHulzVQ".
```


Acknowledgement
---------------

`jose-generator` owes [Nimbus JOSE + JWT library][7] a lot.


Author
------

[Authlete, Inc.][6]


Contact
-------

| Purpose   | Email Address        |
|:----------|:---------------------|
| General   | info@authlete.com    |
| Sales     | sales@authlete.com   |
| PR        | pr@authlete.com      |
| Technical | support@authlete.com |


[1]: https://tools.ietf.org/html/rfc7515
[2]: https://tools.ietf.org/html/rfc7515#appendix-A.5
[3]: https://www.gnu.org/software/bash/manual/html_node/Programmable-Completion-Builtins.html#Programmable-Completion-Builtins
[4]: https://tools.ietf.org/html/rfc7518
[5]: https://tools.ietf.org/html/rfc7518#section-3.1
[6]: https://www.authlete.com/
[7]: https://connect2id.com/products/nimbus-jose-jwt
[8]: https://tools.ietf.org/html/rfc7517
