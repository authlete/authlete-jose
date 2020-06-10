/*
 * Copyright (C) 2018-2020 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.authlete.jose.tool;


import java.io.File;
import java.net.URI;
import com.authlete.jose.tool.converter.Base64UrlConverter;
import com.authlete.jose.tool.converter.FileConverter;
import com.authlete.jose.tool.converter.JWEHeaderBase64UrlConverter;
import com.authlete.jose.tool.converter.JWEHeaderConverter;
import com.authlete.jose.tool.converter.JWKConverter;
import com.authlete.jose.tool.converter.JWKSetConverter;
import com.authlete.jose.tool.converter.JWSHeaderBase64UrlConverter;
import com.authlete.jose.tool.converter.JWSHeaderConverter;
import com.authlete.jose.tool.converter.SupportedEncryptionMethodConverter;
import com.authlete.jose.tool.converter.SupportedJWEAlgorithmConverter;
import com.authlete.jose.tool.converter.SupportedJWSAlgorithmConverter;
import com.authlete.jose.tool.converter.URIConverter;
import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.OptionsBase;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;


public class JoseGeneratorOptions extends OptionsBase
{
    // Category: Operation


    @Option(
        name         = "sign",
        abbrev       = 's',
        defaultValue = "false",
        category     = "Operation",
        help         = "Perform signing"
    )
    public boolean sign;


    @Option(
        name         = "encrypt",
        abbrev       = 'e',
        defaultValue = "false",
        category     = "Operation",
        help         = "Perform encrypting"
    )
    public boolean encrypt;


    @Option(
        name         = "encrypt-then-sign",
        defaultValue = "false",
        category     = "Operation",
        help         = "Specify the order of encrypting and signing in this order"
    )
    public boolean encryptThenSign;


    // Category: Payload


    @Option(
        name         = "payload",
        abbrev       = 'p',
        defaultValue = "null",
        category     = "Payload",
        help         = "Value of the payload"
    )
    public String payload;


    @Option(
        name         = "payload-base64url",
        defaultValue = "null",
        category     = "Payload",
        help         = "Base64url representation of the payload",
        converter    = Base64UrlConverter.class
    )
    public byte[] payloadBase64Url;


    @Option(
        name         = "payload-file",
        defaultValue = "null",
        category     = "Payload",
        help         = "File containing the payload",
        converter    = FileConverter.class
    )
    public File payloadFile;


    @Option(
        name         = "payload-uri",
        defaultValue = "null",
        category     = "Payload",
        help         = "URI of the payload",
        converter    = URIConverter.class
    )
    public URI payloadUri;


    // Category: JWK


    @Option(
        name         = "jwk-signing-alg",
        defaultValue = "null",
        category     = "JWK",
        help         = "JWK for signing (for 'alg' in JWS header)",
        converter    = JWKConverter.class
    )
    public JWK jwkSigningAlg;


    @Option(
        name         = "jwk-signing-alg-file",
        defaultValue = "null",
        category     = "JWK",
        help         = "File of JWK for signing (for 'alg' in JWS header)",
        converter    = FileConverter.class
    )
    public File jwkSigningAlgFile;


    @Option(
        name         = "jwk-signing-alg-uri",
        defaultValue = "null",
        category     = "JWK",
        help         = "URI of JWK for signing (for 'alg' in JWS header)",
        converter    = URIConverter.class
    )
    public URI jwkSigningAlgUri;


    @Option(
        name         = "jwk-encrypting-alg",
        defaultValue = "null",
        category     = "JWK",
        help         = "JWK for encrypting (for 'alg' in JWE header)",
        converter    = JWKConverter.class
    )
    public JWK jwkEncryptingAlg;


    @Option(
        name         = "jwk-encrypting-alg-file",
        defaultValue = "null",
        category     = "JWK",
        help         = "File of JWK for encrypting (for 'alg' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwkEncryptingAlgFile;


    @Option(
        name         = "jwk-encrypting-alg-uri",
        defaultValue = "null",
        category     = "JWK",
        help         = "URI of JWK for encrypting (for 'alg' in JWS header)",
        converter    = URIConverter.class
    )
    public URI jwkEncryptingAlgUri;


    @Option(
        name         = "jwk-encrypting-enc",
        defaultValue = "null",
        category     = "JWK",
        help         = "JWK for encrypting (for 'enc' in JWE header)",
        converter    = JWKConverter.class
    )
    public JWK jwkEncryptingEnc;


    @Option(
        name         = "jwk-encrypting-enc-file",
        defaultValue = "null",
        category     = "JWK",
        help         = "File of JWK for encrypting (for 'enc' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwkEncryptingEncFile;


    @Option(
        name         = "jwk-encrypting-enc-uri",
        defaultValue = "null",
        category     = "JWK",
        help         = "URI of JWK for encrypting (for 'enc' in JWS header)",
        converter    = URIConverter.class
    )
    public URI jwkEncryptingEncUri;


    // Category: JWK Set document


    @Option(
        name         = "jwks",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys (for 'alg' in JWS header, and 'alg' and 'enc' in JWE header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwks;


    @Option(
        name         = "jwks-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys (for 'alg' in JWS header, and 'alg' and 'enc' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwksFile;


    @Option(
        name         = "jwks-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys (for 'alg' in JWS header, and 'alg' and 'enc' in JWE header)",
        converter    = URIConverter.class
    )
    public URI jwksUri;


    @Option(
        name         = "jwks-signing",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwksSigning;


    @Option(
        name         = "jwks-signing-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = FileConverter.class
    )
    public File jwksSigningFile;


    @Option(
        name         = "jwks-signing-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = URIConverter.class
    )
    public URI jwksSigningUri;


    @Option(
        name         = "jwks-signing-alg",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwksSigningAlg;


    @Option(
        name         = "jwks-signing-alg-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = FileConverter.class
    )
    public File jwksSigningAlgFile;


    @Option(
        name         = "jwks-signing-alg-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys for signing (for 'alg' in JWS header)",
        converter    = URIConverter.class
    )
    public URI jwksSigningAlgUri;


    @Option(
        name         = "jwks-encrypting",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys for encrypting (for 'alg' and 'enc' in JWE header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwksEncrypting;


    @Option(
        name         = "jwks-encrypting-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys for encrypting (for 'alg' and 'enc' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwksEncryptingFile;


    @Option(
        name         = "jwks-encrypting-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys for encrypting (for 'alg' and 'enc' in JWE header)",
        converter    = URIConverter.class
    )
    public URI jwksEncryptingUri;


    @Option(
        name         = "jwks-encrypting-alg",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys for encrypting (for 'alg' in JWE header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwksEncryptingAlg;


    @Option(
        name         = "jwks-encrypting-alg-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys for encrypting (for 'alg' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwksEncryptingAlgFile;


    @Option(
        name         = "jwks-encrypting-alg-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys for encrypting (for 'alg' in JWE header)",
        converter    = URIConverter.class
    )
    public URI jwksEncryptingAlgUri;


    @Option(
        name         = "jwks-encrypting-enc",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "JWK Set document containing keys for encrypting (for 'enc' in JWE header)",
        converter    = JWKSetConverter.class
    )
    public JWKSet jwksEncryptingEnc;


    @Option(
        name         = "jwks-encrypting-enc-file",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "File of JWK Set document containing keys for encrypting (for 'enc' in JWE header)",
        converter    = FileConverter.class
    )
    public File jwksEncryptingEncFile;


    @Option(
        name         = "jwks-encrypting-enc-uri",
        defaultValue = "null",
        category     = "JWK Set document",
        help         = "URI of JWK Set document containing keys for encrypting (for 'enc' in JWE header)",
        converter    = URIConverter.class
    )
    public URI jwksEncryptingEncUri;


    // Category: JWS (JSON Web Signature)


    @Option(
        name         = "signing-alg",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "Algorithm for signing (for 'alg' in JWS header)",
        valueHelp    = "Valid values are HS256, HS384, HS512, RS256, RS384, RS512, "
                     + "ES256, ES384, ES512, PS256, PS384, PS512 and none.",
        converter    = SupportedJWSAlgorithmConverter.class
    )
    public JWSAlgorithm signingAlg;


    @Option(
        name         = "signing-alg-kid",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "Key ID of the key for signing"
    )
    public String signingAlgKid;


    @Option(
        name         = "signing-alg-key",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "Key for signing for a symmetric algorithm (HS256, HS384 or HS512)"
    )
    public String signingAlgKey;


    @Option(
        name         = "signing-alg-key-base64url",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "Base64url representation of the key for signing for a symmetric algorithm (HS256, HS384 or HS512)",
        converter    = Base64UrlConverter.class
    )
    public byte[] signingAlgKeyBase64Url;


    @Option(
        name         = "signing-alg-key-file",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "File containing the key for signing for a symmetric algorithm (HS256, HS384 or HS512)",
        converter    = FileConverter.class
    )
    public File signingAlgKeyFile;


    @Option(
        name         = "signing-alg-key-uri",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "URI of the key for signing for a symmetric algorithm (HS256, HS384 or HS512)",
        converter    = URIConverter.class
    )
    public URI signingAlgKeyUri;


    @Option(
        name         = "jws-header",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "JWS header",
        converter    = JWSHeaderConverter.class
    )
    public JWSHeader jwsHeader;


    @Option(
        name         = "jws-header-base64url",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "Base64url representation of the JWS header",
        converter    = JWSHeaderBase64UrlConverter.class
    )
    public JWSHeader jwsHeaderBase64Url;


    @Option(
        name         = "jws-header-file",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "File containing the JWS header",
        converter    = FileConverter.class
    )
    public File jwsHeaderFile;


    @Option(
        name         = "jws-header-uri",
        defaultValue = "null",
        category     = "JWS (JSON Web Signature)",
        help         = "URI of the JWS header",
        converter    = URIConverter.class
    )
    public URI jwsHeaderUri;


    // Category: JWE (JSON Web Encryption)


    @Option(
        name         = "encrypting-alg",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Algorithm for encryption ('alg' in JWE header)",
        valueHelp    = "Valid values are RSA1_5, RSA-OAEP, RSA-OAEP-256, "
                     + "A128KW, A192KW, A256KW, dir, ECDH-ES, "
                     + "ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW, "
                     + "A128GCMKW, A192GCMKW, A256GCMKW, PBES2-HS256+A128KW, "
                     + "PBES2-HS384+A192KW and PBES2-HS512+A256KW.",
        converter    = SupportedJWEAlgorithmConverter.class
    )
    public JWEAlgorithm encryptingAlg;


    @Option(
        name         = "encrypting-alg-kid",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Key ID of the key for encrypting ('alg' in JWE header)"
    )
    public String encryptingAlgKid;


    @Option(
        name         = "encrypting-alg-key",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Key for a symmetric encryption algorithm ('alg' in JWE header)"
    )
    public String encryptingAlgKey;


    @Option(
        name         = "encrypting-alg-key-base64url",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Base64url representation of the key for a symmetric encryption algorithm ('alg' in JWE header)",
        converter    = Base64UrlConverter.class
    )
    public byte[] encryptingAlgKeyBase64Url;


    @Option(
        name         = "encrypting-alg-key-file",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "File containing the key for a symmetric encryption algorithm ('alg' in JWE header)",
        converter    = FileConverter.class
    )
    public File encryptingAlgKeyFile;


    @Option(
        name         = "encrypting-alg-key-uri",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "URI of the key for a symmetric encryption algorithm ('alg' in JWE header)",
        converter    = URIConverter.class
    )
    public URI encryptingAlgKeyUri;


    @Option(
        name         = "encrypting-enc",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Algorithm for encryption ('enc' in JWE header)",
        valueHelp    = "Valid values are A128CBC-HS256, A192CBC-HS384, "
                     + "A256CBC-HS512, A128GCM, A192GCM and A256GCM.",
        converter    = SupportedEncryptionMethodConverter.class
    )
    public EncryptionMethod encryptingEnc;


    @Option(
        name         = "encrypting-enc-kid",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Key ID of the key for encrypting ('enc' in JWE header)"
    )
    public String encryptingEncKid;


    @Option(
        name         = "encrypting-enc-key",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Key for encrypting for a symmetric encryption method ('enc' in JWE header)"
    )
    public String encryptingEncKey;


    @Option(
        name         = "encrypting-enc-key-base64url",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Base64url representation of the key for encrypting for a symmetric encryption method ('enc' in JWE header)",
        converter    = Base64UrlConverter.class
    )
    public byte[] encryptingEncKeyBase64Url;


    @Option(
        name         = "encrypting-enc-key-file",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "File containing the key for encrypting for a symmetric encryption method ('enc' in JWE header)",
        converter    = FileConverter.class
    )
    public File encryptingEncKeyFile;


    @Option(
        name         = "encrypting-enc-key-uri",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "URI of the key for encrypting for a symmetric encryption method ('enc' in JWE header)",
        converter    = URIConverter.class
    )
    public URI encryptingEncKeyUri;


    @Option(
        name         = "jwe-header",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "JWE header",
        converter    = JWEHeaderConverter.class
    )
    public JWEHeader jweHeader;


    @Option(
        name         = "jwe-header-base64url",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "Base64url representation of the JWE header",
        converter    = JWEHeaderBase64UrlConverter.class
    )
    public JWEHeader jweHeaderBase64Url;


    @Option(
        name         = "jwe-header-file",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "File containing the JWE header",
        converter    = FileConverter.class
    )
    public File jweHeaderFile;


    @Option(
        name         = "jwe-header-uri",
        defaultValue = "null",
        category     = "JWE (JSON Web Encryption)",
        help         = "URI of the JWE header",
        converter    = URIConverter.class
    )
    public URI jweHeaderUri;


    // Category: Networking


    @Option(
        name         = "connect-timeout",
        defaultValue = "0",
        category     = "Networking",
        help         = "Connection timeout in milliseconds on fetching data."
    )
    public int connectTimeout;


    @Option(
        name         = "read-timeout",
        defaultValue = "0",
        category     = "Networking",
        help         = "Read timeout in milliseconds on fetching data."
    )
    public int readTimeout;


    // Category: Miscellaneous


    @Option(
        name         = "output-file",
        abbrev       = 'o',
        defaultValue = "null",
        category     = "Miscellaneous",
        help         = "Output file",
        converter    = FileConverter.class
    )
    public File outputFile;


    @Option(
        name         = "verbose",
        abbrev       = 'v',
        defaultValue = "false",
        category     = "Miscellaneous",
        help         = "Verbose reporting"
    )
    public boolean verbose;
}
