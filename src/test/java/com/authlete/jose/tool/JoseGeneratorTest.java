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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.text.ParseException;
import org.junit.Test;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;


public class JoseGeneratorTest
{
    private static final String PAYLOAD = "{\"hello\":\"world\"}";

    private static final String PAYLOAD_BASE64URL = toBase64Url(PAYLOAD);

    // From RFC 7515, A.1.1. Encoding
    private static final String PAYLOAD_RFC7515 =
            "{\"iss\":\"joe\",\r\n" +
            " \"exp\":1300819380,\r\n" +
            " \"http://example.com/is_root\":true}";

    private static final String KEY_256   = "abcdefghijklmnopqrstuvwxyz012345";
    private static final String KEY_256_2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ987654";
    private static final String KEY_384   = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";

    private static final String KEY_256_BASE64URL   = toBase64Url(KEY_256);
    private static final String KEY_256_2_BASE64URL = toBase64Url(KEY_256_2);
    private static final String KEY_384_BASE64URL   = toBase64Url(KEY_384);

    private static final String JWS_HEADER_HS256 = "{\"alg\":\"HS256\"}";

    private static final String JWS_HEADER_HS256_BASE64URL = toBase64Url(JWS_HEADER_HS256);

    private static final String JWK_OCT_256 =
            "{\"kty\":\"oct\"," +
            " \"k\":\"" + KEY_256_BASE64URL + "\"}";

    private static final String JWK_OCT_256_ALG_HS256 =
            "{\"kty\":\"oct\"," +
            " \"k\":\"" + KEY_256_BASE64URL + "\"," +
            " \"alg\":\"HS256\"}";

    // From RFC 7515, A.2.1. Encoding
    private static final String JWK_RSA_RFC7515 =
            "{\"kty\":\"RSA\"," +
            " \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
                     "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
                     "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
                     "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
                     "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
                     "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\"," +
            " \"e\":\"AQAB\"," +
            " \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
                     "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
                     "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
                     "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
                     "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
                     "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"," +
            " \"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
                     "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
                     "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\"," +
            " \"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
                     "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
                     "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\"," +
            " \"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
                     "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
                     "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\"," +
            " \"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
                     "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
                     "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\"," +
            " \"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
                     "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
                     "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"" +
            "}";

    // From RFC 7515, A.3.1. Encoding
    private static final String JWK_EC_RFC7515 =
            "{\"kty\":\"EC\"," +
            " \"crv\":\"P-256\"," +
            " \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"," +
            " \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"," +
            " \"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"" +
            "}";

    private static final String OUTPUT_JWS_HS256 =
            "eyJhbGciOiJIUzI1NiJ9." +
            "eyJoZWxsbyI6IndvcmxkIn0." +
            "cEQMT-o9GifbSdakyzP6M6LJ2pPt0ThvyFXQ1eZjgP4";

    // From RFC 7515, A.2.1. Encoding
    private static final String OUTPUT_JWS_RS256_RFC7515 =
            "eyJhbGciOiJSUzI1NiJ9" +
            "." +
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
            "." +
            "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
            "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
            "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
            "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
            "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
            "p0igcN_IoypGlUPQGe77Rw";

    // From RFC 7515, A.5. Example Unsecured JWS
    private static final String OUTPUT_JWS_UNSECURED_RFC7515 =
            "eyJhbGciOiJub25lIn0" +
            "." +
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
            ".";

    private static final String JWKS_OCT_256 = "{\"keys\":[" + JWK_OCT_256 + "]}";

    private static final String JWKS_OCTS_01 =
            "{\"keys\":[" +
              "{\"kty\":\"oct\"," +
               "\"k\":\"" + KEY_256_2_BASE64URL + "\"," +
               "\"kid\":\"ABC654\"" +
              "}," +
              "{\"kty\":\"oct\"," +
               "\"k\":\"" + KEY_256_BASE64URL + "\"," +
               "\"kid\":\"abc345\"" +
              "}," +
              "{\"kty\":\"oct\"," +
               "\"k\":\"" + KEY_384_BASE64URL + "\"," +
               "\"alg\":\"HS384\"" +
              "}" +
            "]}";

    private static final String JWKS_OCTS_02 =
            "{\"keys\":[" +
              "{\"kty\":\"oct\"," +
               "\"k\":\"" + KEY_256_2_BASE64URL + "\"," +
               "\"alg\":\"HS256\"" +
              "}," +
              "{\"kty\":\"oct\"," +
               "\"k\":\"" + KEY_256_BASE64URL + "\"," +
               "\"alg\":\"HS256\"," +
               "\"kid\":\"abc345\"" +
              "}" +
            "]}";


    private static String toBase64Url(String input)
    {
        return Base64URL.encode(input).toString();
    }


    private static String execute(String[] args)
    {
        try
        {
            return new JoseGenerator()
                    .setStandardError(System.err)
                    .execute(args);
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }


    @Test
    public void test_signing_HS256_01()
    {
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS256",
                "--jwk-signing-alg", JWK_OCT_256,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_HS256_02()
    {
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--jwk-signing-alg", JWK_OCT_256_ALG_HS256,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_HS256_03()
    {
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS256",
                "--signing-alg-key", KEY_256,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_HS256_04()
    {
        String actual = execute(new String[] {
                "--payload-base64url", PAYLOAD_BASE64URL,
                "--sign",
                "--signing-alg", "HS256",
                "--signing-alg-key-base64url", KEY_256_BASE64URL,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_HS256_05()
    {
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg-key", KEY_256,
                "--jws-header", JWS_HEADER_HS256,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_HS256_06()
    {
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg-key", KEY_256,
                "--jws-header-base64url", JWS_HEADER_HS256_BASE64URL,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_signing_RS256_01()
    {
        // RFC 7515, A.2. Example JWS Using RSASSA-PKCS1-v1_5 SHA-256

        String actual = execute(new String[] {
                "--payload", PAYLOAD_RFC7515,
                "--sign",
                "--signing-alg", "RS256",
                "--jwk-signing-alg", JWK_RSA_RFC7515
        });

        assertEquals(OUTPUT_JWS_RS256_RFC7515, actual);
    }


    @Test
    public void test_signing_ES256_01() throws ParseException, JOSEException
    {
        // RFC 7515, A.3. Example JWS Using ECDSA P-256 SHA-256

        String output = execute(new String[] {
                "--payload", PAYLOAD_RFC7515,
                "--sign",
                "--signing-alg", "ES256",
                "--jwk-signing-alg", JWK_EC_RFC7515
        });

        // Parse the output as a JWSObject.
        JWSObject object = JWSObject.parse(output);

        // Verifier to verify the signature.
        ECKey key = (ECKey)JWK.parse(JWK_EC_RFC7515);
        JWSVerifier verifier = new ECDSAVerifier(key);

        // Verify the signature.
        boolean verified = verifier.verify(
                object.getHeader(),
                object.getSigningInput(),
                object.getSignature()
        );

        assertTrue(verified);
    }


    @Test
    public void test_unsecured_01()
    {
        // RFC 7515, A.5. Example Unsecured JWS

        String actual = execute(new String[] {
                "--payload", PAYLOAD_RFC7515,
        });

        assertEquals(OUTPUT_JWS_UNSECURED_RFC7515, actual);
    }


    @Test
    public void test_unsecured_02()
    {
        // RFC 7515, A.5. Example Unsecured JWS

        String actual = execute(new String[] {
                "--payload", PAYLOAD_RFC7515,
                "--sign",
                "--signing-alg", "none"
        });

        assertEquals(OUTPUT_JWS_UNSECURED_RFC7515, actual);
    }


    @Test
    public void test_jwks_01()
    {
        // When the number of JWKs in the given JWK Set document is just 1,
        // the JWK is used.
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS256",
                "--jwks-signing-alg", JWKS_OCT_256,
        });

        assertEquals(OUTPUT_JWS_HS256, actual);
    }


    @Test
    public void test_jwks_02() throws KeyLengthException, JOSEException
    {
        String kid = "abc345";

        // Prepare the expected result.
        JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(kid).build(),
            new Payload(PAYLOAD)
        );
        jwsObject.sign(new MACSigner(KEY_256));
        String expected = jwsObject.serialize();

        // When the key ID is specified, it is used to look up the JWK.
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS256",
                "--jwks-signing-alg", JWKS_OCTS_01,
                "--signing-alg-kid", kid,
        });

        assertEquals(expected, actual);
    }


    @Test
    public void test_jwks_03() throws KeyLengthException, JOSEException
    {
        // Prepare the expected result.
        JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.HS384).build(),
            new Payload(PAYLOAD)
        );
        jwsObject.sign(new MACSigner(KEY_384));
        String expected = jwsObject.serialize();

        // The JWK Set document contains a JWK whose 'alg' is "HS384".
        // The algorithm is used to find the JWK.
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS384",
                "--jwks-signing-alg", JWKS_OCTS_01,
        });

        assertEquals(expected, actual);
    }


    @Test
    public void test_jwks_04() throws KeyLengthException, JOSEException
    {
        // Prepare the expected result.
        JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("ABC654").build(),
            new Payload(PAYLOAD)
        );
        jwsObject.sign(new MACSigner(KEY_256_2));
        String expected = jwsObject.serialize();

        // None of the JWKs in the JWK Set document has "alg":"HS256",
        // so the key type ("kty":"oct") is used to find a proper JWK.
        // This is dependent on the implementation of Nimbus JOSE+JWT
        // library, but we assume that the first JWK in the JWK Set
        // document is selected.
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--signing-alg", "HS256",
                "--jwks-signing-alg", JWKS_OCTS_01,
        });

        assertEquals(expected, actual);
    }


    @Test
    public void test_jwks_05() throws KeyLengthException, JOSEException
    {
        // Prepare the expected result.
        JWSObject jwsObject = new JWSObject(
            new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("abc345").build(),
            new Payload(PAYLOAD)
        );
        jwsObject.sign(new MACSigner(KEY_256));
        String expected = jwsObject.serialize();

        // Even if the '--signing-alg' option is missing, if all the
        // JWKs in the JWK Set document have the 'alg' parameter and
        // all of them have the same value, it is used as the signing
        // algorithm. A JWK having the 'kid' parameter is preferred
        // to other JWKs that don't have the 'kid' parameter.
        String actual = execute(new String[] {
                "--payload", PAYLOAD,
                "--sign",
                "--jwks-signing-alg", JWKS_OCTS_02,
        });

        assertEquals(expected, actual);
    }
}
