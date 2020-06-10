/*
 * Copyright (C) 2018 Authlete, Inc.
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


import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.EncryptionMethod.A128GCM;
import static com.nimbusds.jose.EncryptionMethod.A192CBC_HS384;
import static com.nimbusds.jose.EncryptionMethod.A192GCM;
import static com.nimbusds.jose.EncryptionMethod.A256CBC_HS512;
import static com.nimbusds.jose.EncryptionMethod.A256GCM;
import static com.nimbusds.jose.JWEAlgorithm.A128KW;
import static com.nimbusds.jose.JWEAlgorithm.A192KW;
import static com.nimbusds.jose.JWEAlgorithm.A256KW;
import static com.nimbusds.jose.JWEAlgorithm.DIR;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A128KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A192KW;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A256KW;
import static com.nimbusds.jose.JWEAlgorithm.PBES2_HS256_A128KW;
import static com.nimbusds.jose.JWEAlgorithm.PBES2_HS384_A192KW;
import static com.nimbusds.jose.JWEAlgorithm.PBES2_HS512_A256KW;
import static com.nimbusds.jose.JWEAlgorithm.RSA1_5;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP;
import static com.nimbusds.jose.JWEAlgorithm.RSA_OAEP_256;
import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.ES256K;
import static com.nimbusds.jose.JWSAlgorithm.ES384;
import static com.nimbusds.jose.JWSAlgorithm.ES512;
import static com.nimbusds.jose.JWSAlgorithm.EdDSA;
import static com.nimbusds.jose.JWSAlgorithm.HS256;
import static com.nimbusds.jose.JWSAlgorithm.HS384;
import static com.nimbusds.jose.JWSAlgorithm.HS512;
import static com.nimbusds.jose.JWSAlgorithm.PS256;
import static com.nimbusds.jose.JWSAlgorithm.PS384;
import static com.nimbusds.jose.JWSAlgorithm.PS512;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static com.nimbusds.jose.JWSAlgorithm.RS384;
import static com.nimbusds.jose.JWSAlgorithm.RS512;
import static com.nimbusds.jose.jwk.KeyType.EC;
import static com.nimbusds.jose.jwk.KeyType.OCT;
import static com.nimbusds.jose.jwk.KeyType.OKP;
import static com.nimbusds.jose.jwk.KeyType.RSA;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyType;


public class Support
{
    // Supported 'alg' values in JWS header.
    //
    // Note that "none" is supported but not listed here. In Nimbus
    // JOSE+JWT library, "none" requires special treatment. For example,
    // JWSAlgorithm.parse("HS256") returns JWSAlgorithm.HS256, but
    // JWSAlgorithm.parse("none") returns a new JWSAlgorithm instance.
    private static final JWSAlgorithm[] SUPPORTED_JWS_ALG_VALUES = new JWSAlgorithm[] {
            HS256, HS384, HS512,
            RS256, RS384, RS512,
            ES256, ES384, ES512,
            PS256, PS384, PS512,
            ES256K, EdDSA
    };


    // Supported 'alg' values in JWE header.
    @SuppressWarnings("deprecation")
    private static final JWEAlgorithm[] SUPPORTED_JWE_ALG_VALUES = new JWEAlgorithm[] {
            RSA1_5, RSA_OAEP, RSA_OAEP_256,
            A128KW, A192KW, A256KW,
            DIR, ECDH_ES,
            ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
            PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW
    };


    // Supported 'enc' values in JWE header.
    private static final EncryptionMethod[] SUPPORTED_JWE_ENC_VALUES = new EncryptionMethod[] {
            A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
            A128GCM, A192GCM, A256GCM
    };


    // Supported 'kty' values in JWK.
    private static final KeyType[] SUPPORTED_JWK_KTY_VALUES = new KeyType[] {
            EC, OCT, RSA, OKP
    };


    public static boolean isSupportedJwsAlg(JWSAlgorithm algorithm)
    {
        if (algorithm == null)
        {
            // Not supported.
            return false;
        }

        // Check if the algorithm is included in the list of
        // supported JWS algorithms.
        for (JWSAlgorithm supportedAlgorithm : SUPPORTED_JWS_ALG_VALUES)
        {
            // If the algorithm is included in the list.
            if (algorithm == supportedAlgorithm)
            {
                // Supported.
                return true;
            }
        }

        // In Nimbus JOSE+JWT library, "none" requires special treatment.
        if ("none".equals(algorithm.getName()))
        {
            // Supported.
            return true;
        }

        // Not supported.
        return false;
    }


    public static boolean isSupportedJweAlg(JWEAlgorithm algorithm)
    {
        if (algorithm == null)
        {
            // Not supported.
            return false;
        }

        // Check if the algorithm is included in the list of
        // supported JWE algorithms.
        for (JWEAlgorithm supportedAlgorithm : SUPPORTED_JWE_ALG_VALUES)
        {
            // If the algorithm is included in the list.
            if (algorithm == supportedAlgorithm)
            {
                // Supported.
                return true;
            }
        }

        // Not supported.
        return false;
    }


    public static boolean isSupportedJweEnc(EncryptionMethod method)
    {
        if (method == null)
        {
            // Not supported.
            return false;
        }

        // Check if the method is included in the list of supported
        // encryption methods.
        for (EncryptionMethod supportedMethod : SUPPORTED_JWE_ENC_VALUES)
        {
            // If the method is included in the list.
            if (method == supportedMethod)
            {
                // Supported.
                return true;
            }
        }

        // Not supported.
        return false;
    }


    public static boolean isSupportedJwkKty(KeyType type)
    {
        if (type == null)
        {
            // Not supported.
            return false;
        }

        // Check if the type is included in the list of supported key types.
        for (KeyType supportedType : SUPPORTED_JWK_KTY_VALUES)
        {
            // If the type is included in the list.
            if (type == supportedType)
            {
                // Supported.
                return true;
            }
        }

        // Not supported.
        return false;
    }
}
