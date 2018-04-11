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


import static com.nimbusds.jose.util.StandardCharset.UTF_8;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.security.Provider;
import java.security.Security;
import java.text.ParseException;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * A command line tool to generate JOSE (JavaScript Object Signing and
 * Encryption) in the compact serialization format.
 *
 * For maximum usability, this tool provides various ways to specify
 * payload data, algorithms and keys.
 *
 * @see https://github.com/authlete/authlete-jose/blob/master/doc/JOSE-GENERATOR.md
 */
public class JoseGenerator
{
    /*
     * This represents {"alg":"none"}. See:
     *
     *   A.5. Example Unsecured JWS" in RFC 7515.
     *   https://tools.ietf.org/html/rfc7515#appendix-A.5
     */
    private static final String UNSECURED_JWS_HEADER = "eyJhbGciOiJub25lIn0";

    // Standard input, output and error that execute() method uses.
    private InputStream mStandardInput;
    private PrintStream mStandardOutput;
    private PrintStream mStandardError;

    // JWS header specified by one of the '--jws-header' options.
    private JWSHeader mJwsHeader;

    // The command line option which specified the JWS header.
    private String mJwsHeaderOption;

    // JWK Set document pointed to by the '--jwks-file' option.
    private JWKSet mJwksFromJwksFile;

    // JWK Set document pointed to by the '--jwks-uri' option.
    private JWKSet mJwksFromJwksUri;

    // JWK Set document pointed to by the '--jwks-encrypting-file' option.
    private JWKSet mJwksFromJwksEncryptingFile;

    // JWK Set document pointed to by the '--jwks-encrypting-uri' option.
    private JWKSet mJwksFromJwksEncryptingUri;


    static
    {
        initialize();
    }


    private static void initialize()
    {
        // Initialize BouncyCastle library. This is necessary to support
        // some algorithms additionally. See the following page for details.
        //
        //    "JCA algorithm support"
        //    https://connect2id.com/products/nimbus-jose-jwt/jca-algorithm-support
        //
        Provider bc = BouncyCastleProviderSingleton.getInstance();

        // Add the provider. Note that the JavaDoc of Security.addProvider()
        // says that the method returns "-1 if the provider was not added
        // because it is already installed." This means that multiple calls
        // of addProvider() with the same provider won't cause any trouble.
        Security.addProvider(bc);
    }


    /**
     * The entry point of this program.
     *
     * @param args
     *         The command line arguments.
     */
    public static void main(String[] args)
    {
        try
        {
            new JoseGenerator().useDefaultStandardIO().execute(args);
        }
        catch (Exception e)
        {
            e.printStackTrace(System.err);
            System.err.println("Failed. Try '--verbose' option for detailed reporting.");
            System.exit(1);
        }
    }


    /**
     * Clear the standard I/O settings and internal cache.
     *
     * @return
     *         {@code this} object.
     */
    public JoseGenerator reset()
    {
        mStandardInput  = null;
        mStandardOutput = null;
        mStandardError  = null;

        mJwsHeader       = null;
        mJwsHeaderOption = null;

        mJwksFromJwksFile           = null;
        mJwksFromJwksUri            = null;
        mJwksFromJwksEncryptingFile = null;
        mJwksFromJwksEncryptingUri  = null;

        return this;
    }


    /**
     * Set up the internal I/O to use {@code System.in}, {@code System.out}
     * and {@code System.err}.
     *
     * @return
     *         {@code this} object.
     */
    public JoseGenerator useDefaultStandardIO()
    {
        mStandardInput  = System.in;
        mStandardOutput = System.out;
        mStandardError  = System.err;

        return this;
    }


    /**
     * Get the standard input for this application.
     *
     * @return
     *         The standard input for this application.
     */
    public InputStream getStandardInput()
    {
        return mStandardInput;
    }


    /**
     * Set the standard input for this application.
     *
     * @param in
     *         The stream to be used as the standard input.
     *
     * @return
     *         {@code this} object.
     */
    public JoseGenerator setStandardInput(InputStream in)
    {
        mStandardInput = in;

        return this;
    }


    /**
     * Get the standard output for this application.
     *
     * @return
     *         The standard output for this application.
     */
    public PrintStream getStandardOutput()
    {
        return mStandardOutput;
    }


    /**
     * Set the standard output for this application.
     *
     * @param out
     *         The stream to be used as the standard output.
     *
     * @return
     *         {@code this} object.
     */
    public JoseGenerator setStandardOutput(PrintStream out)
    {
        mStandardOutput = out;

        return this;
    }


    /**
     * Get the standard error for this application.
     *
     * @return
     *         The standard error for this application.
     */
    public PrintStream getStandardError()
    {
        return mStandardError;
    }


    /**
     * Set the standard error for this application.
     *
     * @param err
     *         The stream to be used as the standard error.
     *
     * @return
     *         {@code this} object.
     */
    public JoseGenerator setStandardError(PrintStream err)
    {
        mStandardError = err;

        return this;
    }


    /**
     * Generate a JOSE string.
     *
     * @param args
     *         Command line options.
     *
     * @return
     *         A generated JOSE string.
     */
    public String execute(String[] args) throws IOException, ParseException, JOSEException
    {
        // Parse the command line options.
        JoseGeneratorOptions options =
                new JoseGeneratorOptionsParser().parse(args);

        // Prepare the payload.
        verbose(options, "Reading the payload.");
        byte[] payload = readPayload(options);

        // Wrap the payload.
        verbose(options, "Wrapping the payload.");
        String wrapped = wrapPayload(options, payload);

        // Write the result.
        verbose(options, "Writing the result: %s", wrapped);
        output(options, wrapped);

        // Done.
        verbose(options, "Done.");

        return wrapped;
    }


    private byte[] readPayload(JoseGeneratorOptions options) throws IOException
    {
        // If the '--payload' option was given.
        if (options.payload != null)
        {
            verbose(options, "Using the value specified by the '--payload' option "
                           + "as the value of the payload.");
            return options.payload.getBytes(UTF_8);
        }

        // If the '--payload-base64url' option was given.
        if (options.payloadBase64Url != null)
        {
            verbose(options, "Using the value specified by the '--payload-base64url' "
                           + "option as the value of the payload.");
            return options.payloadBase64Url;
        }

        // If the '--payload-file' option was given.
        if (options.payloadFile != null)
        {
            verbose(options, "Using the content of the file specified by the "
                           + "'--payload-file' option as the value of the payload.");
            return FileUtils.readFileToByteArray(options.payloadFile);
        }

        // If the '--payload-uri' option was given.
        if (options.payloadUri != null)
        {
            verbose(options, "Using the content pointed to by the '--payload-uri' "
                           + "option as the value of the payload.");
            return IOUtils.toByteArray(options.payloadUri);
        }

        // If none of '--payload[-*]' options was given.

        // Get the standard input to read the payload from.
        InputStream in = getStandardInput();
        if (in == null)
        {
            throw fatal(null, "The standard input is not available, so the payload data cannot be read.");
        }

        // Read the standard input and use the content as the value of the payload.
        verbose(options, "Reading the standard input as the value of the payload.");
        return IOUtils.toByteArray(in);
    }


    private String wrapPayload(JoseGeneratorOptions options, byte[] payload) throws IOException, ParseException, JOSEException
    {
        String wrapped;

        // If signing is required.
        if (options.sign)
        {
            // If encrypting is required.
            if (options.encrypt)
            {
                // Both signing and encrypting.
                wrapped = signAndEncrypt(options, payload);
            }
            else
            {
                // Signing only.
                verbose(options, "Generating a JWS. Encrypting is not performed because "
                               + "the '--encrypt' option was not given.");
                wrapped = sign(options, payload);
                verbose(options, "The genrated JWS is %s", wrapped);
            }
        }
        else if (options.encrypt)
        {
            // Encrypting only.
            verbose(options, "Generating a JWE. Signing is not performed because the "
                           + "'--sign' option was not given.");
            wrapped = encrypt(options, payload);
            verbose(options, "The generated JWE is %s", wrapped);
        }
        else
        {
            // No signing and encrypting (-> Unsecured JWS)
            verbose(options, "Generating an unsecured JWS because neither the '--sign' "
                           + "option nor the '--encrypt' option was given.");
            wrapped = unsecure(options, payload);
            verbose(options, "The generated unsecured JWS is %s", wrapped);
        }

        return wrapped;
    }


    private void output(JoseGeneratorOptions options, String value) throws IOException
    {
        // If an output file was specified by the '--output-file' option.
        if (options.outputFile != null)
        {
            // Write the result to the file.
            verbose(options, "Writing the result to the file '%s'.", options.outputFile);
            FileUtils.write(options.outputFile, value, UTF_8);
            return;
        }

        // Get the standard output to write the result to.
        PrintStream out = getStandardOutput();
        if (out == null)
        {
            verbose(options, "The standard output is not available, so the output is not written.");
            return;
        }

        // Write the result to the standard output.
        verbose(options, "Writing the result to the standard output.");
        IOUtils.write(value, out, UTF_8);
        out.flush();
    }


    private String signAndEncrypt(JoseGeneratorOptions options, byte[] payload) throws IOException, ParseException, JOSEException
    {
        // If the order is 'encrypt and then sign'.
        if (options.encryptThenSign)
        {
            verbose(options, "Generating a JWS which wraps a JWE.");

            // Encrypt
            String jwe    = encrypt(options, payload);
            byte[] nested = jwe.getBytes(UTF_8);
            verbose(options, "The generated JWE that will be wrapped is %s", jwe);

            // and then sign
            String jws = sign(options, nested);
            verbose(options, "The generated JWS that wraps the JWE is %s", jws);

            return jws;
        }
        else
        {
            verbose(options, "Generating a JWE which wraps a JWS.");

            // Sign
            String jws     = sign(options, payload);
            byte[] nested  = jws.getBytes(UTF_8);
            verbose(options, "The genrated JWS that will be wrapped is %s", jws);

            // and then encrypt
            String jwe = encrypt(options, nested);
            verbose(options, "The generated JWE that wraps the JWS is %s", jwe);

            return jwe;
        }
    }


    private String sign(JoseGeneratorOptions options, byte[] payload) throws IOException, ParseException, JOSEException
    {
        verbose(options, "Signing.");

        // Get a JWS header specified by one of the --jws-header[-*] options.
        // The call of processJwsHeaderOption() method sets up mJwsHeader and
        // mJwsHeaderOption.
        //
        // Note that if a JWS header is available, its 'alg' is not "none".
        // It's because JWSHeader.parse(String) method throws an exception
        // when the 'alg' parameter of the given JSON is "none". This behavior
        // requires developers handle unsecured JWS in a special way, but
        // this developer-unfriendly requirement is the policy of the authors
        // of Nimbus JOSE + JWT library.
        processJwsHeaderOption(options);

        // Order for looking up a key for signing:
        //
        //   * --signing-alg none      // Key for signing is not needed.
        //
        //   * signing algorithm == HS??? && --signing-alg-key
        //   * signing algorithm == HS??? && --signing-alg-key-base64url
        //   * signing algorithm == HS??? && --signing-alg-key-file
        //   * signing algorithm == HS??? && --signing-alg-key-uri
        //
        //   * --jwk-signing-alg       {JWK}
        //   * --jwk-signing-alg-file  {File of JWK}
        //   * --jwk-signing-alg-uri   {URI of JWK}
        //
        //   * --jwks-signing-alg      {JWKSet}
        //   * --jwks-signing-alg-file {File of JWKSet}
        //   * --jwks-signing-alg-uri  {URI of JWKSet}
        //
        //   * --jwks-signing          {JWKSet}
        //   * --jwks-signing-file     {File of JWKSet}
        //   * --jwks-signing-uri      {URI of JWKSet}
        //
        //   * --jwks                  {JWKSet}
        //   * --jwks-file             {File of JWKSet}
        //   * --jwks-uri              {URI of JWKSet}

        // Signing algorithm specified by the '--signing-alg' option or
        // the 'alg' value of the JWS header specified by one of the
        // '--jws-header[-*]' options. Inconsistency between the value
        // specified by the '--signing-alg' option and the value specified
        // by one of the '--jws-header[-*]' is checked in getSigningAlg().
        JWSAlgorithm alg = getSigningAlg(options, mJwsHeader, mJwsHeaderOption);

        // If a signing algorithm was specified by the '--signing-alg' option
        // or the JWS header specified by one of the '--jws-header[-*]' options,
        // and if the algorithm is 'none'.
        if (alg != null && alg.getName().equals("none"))
        {
            String msg = (options.signingAlg != null)
                       ? "by the '--signing-alg' option."
                       : "by the 'alg' parameter in the JWS header specified by the "
                       + mJwsHeaderOption + " option";
            verbose(options, "Creating an unsecured JWS because 'none' is specified " + msg);
            return unsecure(options, payload);
        }

        // If a signing algorithm was specified and the algorithm is
        // symmetric (HS256, HS384 or HS512).
        if (alg != null && alg.getName().startsWith("HS"))
        {
            // Try to sign using the key specified by one of the
            // '--signing-alg-key[-*]' options.
            String signed = signUsingKeyOrKeyFileOrKeyUri(options, payload, alg);
            if (signed != null)
            {
                return signed;
            }
        }

        // Try to sign using the JWK specified by one of the '--jwk-signing-alg[-*]' options.
        String signed = signUsingJwkSigningAlg(options, payload);
        if (signed != null)
        {
            return signed;
        }

        // Try to sign using the JWK Set document specified by one of the
        // '--jwks-signing-alg[-*]' options.
        signed = signUsingJWKSetOrJWKSetFileOrJWKSetUri(options, payload,
                options.jwksSigningAlg,     "--jwks-signing-alg",
                options.jwksSigningAlgFile, "--jwks-signing-alg-file", null, null,
                options.jwksSigningAlgUri,  "--jwks-signing-alg-uri",  null, null);
        if (signed != null)
        {
            return signed;
        }

        // Try to sign using the JWK Set document specified by one of the
        // '--jwks-signing[-*]' options.
        signed = signUsingJWKSetOrJWKSetFileOrJWKSetUri(options, payload,
                options.jwksSigning,     "--jwks-signing",
                options.jwksSigningFile, "--jwks-signing-file", null, null,
                options.jwksSigningUri,  "--jwks-signing-uri",  null, null);
        if (signed != null)
        {
            return signed;
        }

        // Try to sign using the JWK Set document specified by one of the
        // '--jwks[-*]' options.
        JWKSet[] obtainedFromFile = new JWKSet[1];
        JWKSet[] obtainedFromUri  = new JWKSet[1];
        signed = signUsingJWKSetOrJWKSetFileOrJWKSetUri(options, payload,
                options.jwks,     "--jwks",
                options.jwksFile, "--jwks-file", mJwksFromJwksFile, obtainedFromFile,
                options.jwksUri,  "--jwks-uri",  mJwksFromJwksUri,  obtainedFromUri);

        // Cache the JWK Set document because it might be used later for encrypting.
        if (obtainedFromFile[0] != null)
        {
            mJwksFromJwksFile = obtainedFromFile[0];
        }
        if (obtainedFromUri[0] != null)
        {
            mJwksFromJwksUri = obtainedFromUri[0];
        }

        if (signed != null)
        {
            return signed;
        }

        // Key for signing is not available.
        throw fatal(null,
                "Key for signing is not available. Use '--jwk-signing-alg[-*] option or " +
                "'--jwks[-signing[-alg]][-file|-uri]' option. In addtion, if the signing " +
                "algorithm is symmetric (HS256/HS384/HS512), '--signing-alg-key[-*]' " +
                "options can be used.");
    }


    private void processJwsHeaderOption(JoseGeneratorOptions options) throws IOException, ParseException
    {
        // If the --jws-header option was given.
        if (options.jwsHeader != null)
        {
            mJwsHeader       = options.jwsHeader;
            mJwsHeaderOption = "--jws-header";
        }
        // If the --jws-header-base64url option was given.
        else if (options.jwsHeaderBase64Url != null)
        {
            mJwsHeader       = options.jwsHeaderBase64Url;
            mJwsHeaderOption = "--jws-header-base64url";
        }
        // If the --jws-header-file option was given.
        else if (options.jwsHeaderFile != null)
        {
            // Read the JWS header specified by the --jws-header-file option.
            JWSHeader header = readJWSHeader(options, options.jwsHeaderFile, "--jws-header-file");
            mJwsHeader       = header;
            mJwsHeaderOption = "--jws-header-file";
        }
        // If the --jws-header-uri option was given.
        else if (options.jwsHeaderUri != null)
        {
            // Fetch the JWS header specified by the --jws-header-uri option.
            JWSHeader header = fetchJWSHeader(options, options.jwsHeaderUri, "--jws-header-uri");
            mJwsHeader       = header;
            mJwsHeaderOption = "--jws-header-uri";
        }
        // If none of the '--jws-header[-*]' options was given.
        else
        {
            return;
        }

        verbose(options, "Using the JWS header specified by the '%s' option.", mJwsHeaderOption);
        verbose(options, "The value of the specified JWS header is %s", mJwsHeader);
    }


    private JWSHeader readJWSHeader(JoseGeneratorOptions options, File file, String option) throws IOException, ParseException
    {
        verbose(options, "Reading the JWS header pointed to by the '%s' option. (%s)", option, file);
        String content = FileUtils.readFileToString(file, UTF_8);

        verbose(options, "Converting the content of the file (%s) into a JWS header.", file);
        return JWSHeader.parse(content);
    }


    private JWSHeader fetchJWSHeader(JoseGeneratorOptions options, URI uri, String option) throws IOException, ParseException
    {
        verbose(options, "Fetching the JWS header pointed to by the '%s' option. (%s)", option, uri);
        String content = IOUtils.toString(uri, UTF_8);

        verbose(options, "Converting the content of the URI (%s) into a JWS header.", uri);
        return JWSHeader.parse(content);
    }


    private JWSAlgorithm getSigningAlg(JoseGeneratorOptions options, JWSHeader header, String headerOption)
    {
        // The algorithm specified by the '--signing-alg' option.
        JWSAlgorithm algBySigningAlg = options.signingAlg;

        // The algorithm in the JWS specified by one of the '--jws-header[-*]' options.
        JWSAlgorithm algByJwsHeader = (header == null) ? null : header.getAlgorithm();

        // If the '--signing-alg' option was not given.
        if (algBySigningAlg == null)
        {
            // Use the algorithm in the JWS specified by one of the '--jws-header-[-*]'
            // options. This may be null, too.
            return algByJwsHeader;
        }

        // If none of the '--jws-header[-*]' options was given.
        if (algByJwsHeader == null)
        {
            // Use the algorithm specified by the '--signing-alg' option.
            return algBySigningAlg;
        }

        // Both the '--signing-alg' option and one of the '--jws-header[-*]' options
        // were given. Inconsistency between them is checked here.
        if (algBySigningAlg.getName().equals(algByJwsHeader.getName()))
        {
            // They matched. There is no inconsistency.
            return algBySigningAlg;
        }

        // Inconsistency.
        throw fatal(null, "The signing algorithm specified by the '--signing-alg' "
                        + "option (%s) and the algorithm in the JWS header specified "
                        + "by the '%s' option (%s) do not match.",
                        algBySigningAlg.getName(), headerOption, algByJwsHeader.getName());
    }


    private String signUsingKeyOrKeyFileOrKeyUri(
            JoseGeneratorOptions options, byte[] payload, JWSAlgorithm alg) throws IOException, JOSEException
    {
        // Determine the key from one of the '--signing-alg-key[-*]' options.
        byte[] key = determineKeyFromSigningAlgKeyOptions(options);

        // If no key is available.
        if (key == null)
        {
            // None of the '--signing-alg-key[-*]' options was given.
            return null;
        }

        // Create a JWS object which consists of a JWS header and a payload.
        JWSObject jwsObject = createJwsObject(alg, null, payload);

        // Create a signer, assuming the algorithm is symmetric.
        JWSSigner signer = new MACSigner(key);

        // Sign.
        jwsObject.sign(signer);

        // Convert to a JWS.
        return jwsObject.serialize();

    }


    private byte[] determineKeyFromSigningAlgKeyOptions(JoseGeneratorOptions options) throws IOException
    {
        // If the '--signing-alg-key' option was given.
        if (options.signingAlgKey != null)
        {
            verbose(options, "Using the key specified by the "
                           + "'--signing-alg-key' option for signing.");
            return options.signingAlgKey.getBytes(UTF_8);
        }

        // If the '--signing-alg-key-base64url' option was given.
        if (options.signingAlgKeyBase64Url != null)
        {
            verbose(options, "Using the key specified by the "
                           + "'--signing-alg-key-base64url' option for signing.");
            return options.signingAlgKeyBase64Url;
        }

        // If the '--signing-alg-key-file' option was given.
        if (options.signingAlgKeyFile != null)
        {
            verbose(options, "Using the key specified by the "
                           + "'--signing-alg-key-file' option for signing.");
            return FileUtils.readFileToByteArray(options.signingAlgKeyFile);
        }

        // If the '--signing-alg-key-uri' option was given.
        if (options.signingAlgKeyUri != null)
        {
            verbose(options, "Using the key specified by the "
                           + "'--signing-alg-key-uri' option for signing.");
            return IOUtils.toByteArray(options.signingAlgKeyUri);
        }

        // If none of '--signing-alg-key[-*]' options was given.
        return null;
    }


    private String signUsingJwkSigningAlg(JoseGeneratorOptions options, byte[] payload)
            throws JOSEException, IOException, ParseException
    {
        // If the '--jwk-signing-alg' option was given.
        if (options.jwkSigningAlg != null)
        {
            verbose(options, "Signing using the JWK specified by the '--jwk-signing-alg' option.");
            return signUsingJWK(options, payload, options.jwkSigningAlg);
        }

        // If the '--jwk-signing-alg-file' option was given.
        if (options.jwkSigningAlgFile != null)
        {
            JWK jwk = readJWK(options, options.jwkSigningAlgFile, "--jwk-signing-alg-file");
            verbose(options, "Signing using the JWK specified by the '--jwk-signing-alg-file' option.");
            return signUsingJWK(options, payload, jwk);
        }

        // If the '--jwk-signing-alg-uri' option was given.
        if (options.jwkSigningAlgUri != null)
        {
            JWK jwk = fetchJWK(options, options.jwkSigningAlgUri, "--jwk-signing-alg-uri");
            verbose(options, "Signing using the JWK specified by the '--jwk-signing-alg-uri' option.");
            return signUsingJWK(options, payload, jwk);
        }

        // None of the '--jwk-signing-alg[-*]' option was given.
        return null;
   }


    private String signUsingJWK(JoseGeneratorOptions options, byte[] payload, JWK jwk) throws JOSEException
    {
        verbose(options, "Signing with a JWK.");

        // Check if the key IDs specified by the following are consistent.
        //
        //   1. The key ID specified by the '--signing-alg-kid' option.
        //   2. The key ID specified by the 'kid' parameter in the JWS
        //      header specified by one of the '--jws-header[-*]' options.
        //   3. The key ID specified by the 'kid' parameter in the JWK.
        //
        checkKidForSigning(options, jwk);

        // Check if the algorithms specified by the following are consistent.
        //
        //   1. The algorithm specified by the '--signing-alg' option.
        //   2. The algorithm specified by the 'alg' parameter in the JWS
        //      header specified by one of the '--jws-header[-*]' options.
        //   3. The algorithm specified by the 'alg' parameter in the JWK.
        //
        checkAlgForSigning(options, jwk);

        // Determine the algorithm for signing.
        JWSAlgorithm alg = determineAlgForSigning(options, jwk);

        // The key type of the JWK.
        KeyType kty = jwk.getKeyType();
        if (Support.isSupportedJwkKty(kty) == false)
        {
            throw fatal(null, "The 'kty' (%s) in the JWK is not supported.", kty);
        }

        // Create a JWS object which consists of a JWS header and a payload.
        //
        // If none of the '--jws-header[-*]' options was given, createJwsObject()
        // will create a JWSHeader instance which includes an 'alg' parameter and
        // optionally a 'kid' parameter.
        JWSObject jwsObject = createJwsObject(alg, jwk.getKeyID(), payload);

        // Create a signer.
        JWSSigner signer = createSigner(options, kty, jwk);

        // Sign.
        jwsObject.sign(signer);

        // Convert to a JWS.
        return jwsObject.serialize();
    }


    private JWK readJWK(JoseGeneratorOptions options, File file, String option) throws IOException, ParseException
    {
        verbose(options, "Reading the JWK pointed to by the '%s' option. (%s)", option, file);
        String content = FileUtils.readFileToString(file, UTF_8);

        verbose(options, "Converting the content of the file (%s) into a JWK.", file);
        return JWK.parse(content);
    }


    private JWK fetchJWK(JoseGeneratorOptions options, URI uri, String option) throws IOException, ParseException
    {
        verbose(options, "Fetching the JWK pointed to by the '%s' option. (%s)", option, uri);
        String content = IOUtils.toString(uri, UTF_8);

        verbose(options, "Converting the content of the URI (%s) into a JWK.", uri);
        return JWK.parse(content);
    }


    private void checkKidForSigning(JoseGeneratorOptions options, JWK jwk)
    {
        // 1. The key ID specified by the '--signing-alg-kid' option.
        String keyIdBySigningAlgKid = options.signingAlgKid;

        // 2. The key ID specified by the 'kid' parameter in the JWS header
        //    specified by one of the '--jws-header[-*]' options.
        String keyIdInJwsHeader = (mJwsHeader == null) ? null : mJwsHeader.getKeyID();

        // 3. The key ID specified by the 'kid' parameter in the JWK.
        String keyIdInJwk = jwk.getKeyID();

        if (keyIdBySigningAlgKid == null)
        {
            if (keyIdInJwsHeader == null || keyIdInJwk == null ||
                keyIdInJwsHeader.equals(keyIdInJwk))
            {
                return;
            }

            throw fatal(null, "The key ID (%s) in the JWS header specified by the '%s' option "
                            + "and the key ID (%s) in the JWK are different.",
                            keyIdInJwsHeader, mJwsHeaderOption, keyIdInJwk);
        }

        if (keyIdInJwsHeader == null)
        {
            if (keyIdInJwk == null || keyIdBySigningAlgKid.equals(keyIdInJwk))
            {
                return;
            }

            throw fatal(null, "The key ID (%s) specified by the '--signing-alg-kid' option "
                            + "and the key ID (%s) in the JWK are different.",
                            keyIdBySigningAlgKid, keyIdInJwk);
        }

        if (keyIdBySigningAlgKid.equals(keyIdInJwsHeader) == false)
        {
            throw fatal(null, "The key ID (%s) specified by the '--signing-alg-kid' option "
                            + "and the key ID (%s) in the JWS header specified by the '%s' "
                            + "option are different.",
                            keyIdBySigningAlgKid, keyIdInJwsHeader, mJwsHeaderOption);
        }

        if (keyIdInJwk == null)
        {
            return;
        }

        throw fatal(null, "The key ID (%s) specified by the '--signing-alg-kid' option "
                        + "and the key ID (%s) in the JWK are different.",
                        keyIdBySigningAlgKid, keyIdInJwk);
    }


    private void checkAlgForSigning(JoseGeneratorOptions options, JWK jwk)
    {
        // 1. The algorithm specified by the '--signing-alg' option.
        String algBySigningAlg = (options.signingAlg == null) ? null : options.signingAlg.getName();

        // 2. The algorithm specified by the 'alg' parameter in the JWS header
        //    specified by one of the '--jws-header[-*]' options.
        String algInJwsHeader = (mJwsHeader == null || mJwsHeader.getAlgorithm() == null)
                              ? null : mJwsHeader.getAlgorithm().getName();

        // 3. The algorithm specified by the 'alg' parameter in the JWK.
        String algInJwk = (jwk.getAlgorithm() == null) ? null : jwk.getAlgorithm().getName();

        if (algBySigningAlg == null)
        {
            if (algInJwsHeader == null || algInJwk == null || algInJwsHeader.equals(algInJwk))
            {
                return;
            }

            throw fatal(null, "The algorithm (%s) in the JWS header specified by the '%s' option "
                            + "and the algorithm (%s) in the JWK are different.",
                            algInJwsHeader, mJwsHeaderOption, algInJwk);
        }

        if (algInJwsHeader == null)
        {
            if (algInJwk == null || algBySigningAlg.equals(algInJwk))
            {
                return;
            }

            throw fatal(null, "The algorithm (%s) specified by the '--signing-alg' option "
                            + "and the algorithm (%s) in the JWK are different.",
                            algBySigningAlg, algInJwk);
        }

        if (algBySigningAlg.equals(algInJwsHeader) == false)
        {
            throw fatal(null, "The algorithm (%s) specified by the '--signing-alg' option "
                            + "and the algorithm (%s) in the JWS header specified by the '%s' "
                            + "option are different.",
                            algBySigningAlg, algInJwsHeader, mJwsHeaderOption);
        }

        if (algInJwk == null)
        {
            return;
        }

        throw fatal(null, "The algorithm (%s) specified by the '--signing-alg' option "
                        + "and the algorithm (%s) in the JWK are different.",
                        algBySigningAlg, algInJwk);
    }


    private JWSAlgorithm determineAlgForSigning(JoseGeneratorOptions options, JWK jwk)
    {
        // If the algorithm was explicitly specified by the '--signing-alg' option.
        if (options.signingAlg != null)
        {
            // Use the algorithm specified by the '--signing-alg' option.
            return options.signingAlg;
        }

        // If a JWS header was given by one of the '--jws-header[-*]' options.
        if (mJwsHeader != null)
        {
            // 'alg' in the JWS header.
            JWSAlgorithm signingAlg = mJwsHeader.getAlgorithm();

            // If the JWS header contains the 'alg' parameter.
            if (signingAlg != null)
            {
                // If the value of the 'alg' parameter is supported.
                if (Support.isSupportedJwsAlg(signingAlg))
                {
                    return signingAlg;
                }

                throw fatal(null, "The value (%s) of the 'alg' parameter in the JWS header "
                                + "specified by the '%s' option is not supported.",
                                signingAlg.getName(), mJwsHeaderOption);
            }
        }

        // 'alg' in the JWK.
        Algorithm alg = jwk.getAlgorithm();

        if (alg == null)
        {
            throw fatal(null, "The JWK does not have 'alg', so the algorithm for signing "
                            + "must be specified explicitly by the '--signing-alg' option or "
                            + "by the 'alg' parameter in the JWS header specified by one of "
                            + "the '--jws-header[-*]' options.");
        }

        // Parse the 'alg' as a JWSAlgorithm.
        JWSAlgorithm signingAlg = JWSAlgorithm.parse(alg.getName());

        // If the 'alg' is supported.
        if (Support.isSupportedJwsAlg(signingAlg))
        {
            return signingAlg;
        }

        // The 'alg' in the JWK is not supported.
        throw fatal(null, "The value (%s) of the 'alg' parameter in the JWK is not supported.", alg.getName());
    }


    private String signUsingJWKSetOrJWKSetFileOrJWKSetUri(
            JoseGeneratorOptions options, byte[] payload,
            JWKSet jwks, String jwksOption,
            File jwksFile, String jwksFileOption, JWKSet cachedJwksFromFile, JWKSet[] obtainedJwksFromFile,
            URI jwksUri, String jwksUriOption, JWKSet cachedJwksFromUri, JWKSet[] obtainedJwksFromUri) throws IOException, ParseException, JOSEException
    {
        // If a JWK Set document for signing is available.
        if (jwks != null)
        {
            // Sign using the JWK Set document specified by the '--jwks[-*]' option.
            return signUsingJWKSet(options, payload, jwks, jwksOption);
        }

        // If a file of JWK Set document is available.
        if (jwksFile != null)
        {
            // If the cache of the file is available.
            if (cachedJwksFromFile != null)
            {
                // Sign using the cached JWK Set document.
                return signUsingJWKSet(options, payload, cachedJwksFromFile, jwksFileOption);
            }

            // Read the JWK Set document pointed to by the '--jwks[-*]-file option.
            JWKSet jwkset = readJWKSet(options, jwksFile, jwksFileOption);

            // Cache the obtained JWK Set document if required.
            if (obtainedJwksFromFile != null)
            {
                obtainedJwksFromFile[0] = jwkset;
            }

            // Sign using the JWK Set document pointed to by the '--jwks[-*]-file' option.
            return signUsingJWKSet(options, payload, jwkset, jwksFileOption);
        }

        // If a URI of JWK Set document is available.
        if (jwksUri != null)
        {
            // If the cache of the content of the URI is available.
            if (cachedJwksFromUri != null)
            {
                // Sign using the cached JWK Set document.
                return signUsingJWKSet(options, payload, cachedJwksFromUri, jwksUriOption);
            }

            // Fetch the JWK Set document pointed to by the '--jwks[-*]-uri' option.
            JWKSet jwkset = fetchJWKSet(options, jwksUri, jwksUriOption);

            // Cache the obtained JWK Set document if required.
            if (obtainedJwksFromUri != null)
            {
                obtainedJwksFromUri[0] = jwkset;
            }

            // Sign using the JWK Set document pointed to by the '--jwks[-*]-uri' option.
            return signUsingJWKSet(options, payload, jwkset, jwksUriOption);
        }

        return null;
    }


    private JWSSigner createSigner(JoseGeneratorOptions options, KeyType kty, JWK jwk) throws JOSEException
    {
        verbose(options, "Creating a signer for the key type (%s).", kty);

        if (kty == KeyType.EC)
        {
            return new ECDSASigner((ECKey)jwk);
        }

        if (kty == KeyType.OCT)
        {
            return new MACSigner((OctetSequenceKey)jwk);
        }

        if (kty == KeyType.RSA)
        {
            return new RSASSASigner((RSAKey)jwk);
        }

        throw fatal(null, "Cannot create a signer for the key type (%s).", kty);
    }


    private String signUsingJWKSet(
            JoseGeneratorOptions options, byte[] payload, JWKSet jwks, String option) throws JOSEException
    {
        verbose(options, "Signing using the JWK Set document specified by the '%s' option.", option);

        // Keys in the JWK Set.
        List<JWK> keys = jwks.getKeys();

        // If the JWK Set document does not contain keys.
        if (keys == null || keys.size() == 0)
        {
            throw fatal(null, "The JWK Set document specified by the '%s' option does not contain keys.", option);
        }

        // If the number of keys in the JWK Set document is 1.
        if (keys.size() == 1)
        {
            // Use the JWK.
            verbose(options, "The number of keys in the JWK Set document is 1, so the JWK is used for signing.");
            return signUsingJWK(options, payload, keys.get(0));
        }

        // If a key ID is given by command line options, try to find the JWK
        // having the key ID and perform signing with the JWK.
        String signed = signUsingJWKSetByKid(options, payload, keys);
        if (signed != null)
        {
            return signed;
        }

        // Determine the algorithm for signing. Basically, the algorithm specified
        // by the '--signing-alg' option or the algorithm specified by the 'alg'
        // parameter in the JWS header specified by one of the '--jws-header[-*]'
        // options is used. If both of them don't have value, as a special fallback,
        // if all the keys in the JWK Set document have the 'alg' parameter and their
        // values are identical, the algorithm is picked up.
        JWSAlgorithm alg = determineSigningAlg(options, keys);

        // Try to find a JWK having the signing algorithm and perform signing
        // with the JWK.
        signed = signUsingJWKSetByAlg(options, payload, keys, alg);
        if (signed != null)
        {
            return signed;
        }

        // Try to find a JWK having an appropriate key type for the signing algorithm
        // and perform signing with the JWK.
        signed = signUsingJWKSetByKty(options, payload, jwks, alg);
        if (signed != null)
        {
            return signed;
        }

        throw fatal(null, "Could not find any appropriate JWK for the algorithm (%s) for signing.", alg.getName());
    }


    private JWKSet readJWKSet(JoseGeneratorOptions options, File file, String option) throws IOException, ParseException
    {
        verbose(options, "Reading the JWK Set document pointed to by the '%s' option. (%s)", option, file);

        return JWKSet.load(file);
    }


    private JWKSet fetchJWKSet(JoseGeneratorOptions options, URI uri, String option) throws IOException, ParseException
    {
        verbose(options, "Fetching the JWK Set document pointed to by the '%s' option. (%s)", option, uri);

        return JWKSet.load(uri.toURL(), options.connectTimeout, options.readTimeout, 0);
    }


    private String signUsingJWKSetByKid(
            JoseGeneratorOptions options, byte[] payload, List<JWK> keys) throws JOSEException
    {
        // The key ID specified by the '--signing-alg-kid' option or by the 'kid'
        // parameter in the JWS header specified by one of the '--jws-header[-*]' options.
        // Inconsistency that might exist between the key IDs are checked in signUsingJWK().
        String kid = (options.signingAlgKid != null) ? options.signingAlgKid
                   : ((mJwsHeader != null) ? mJwsHeader.getKeyID() : null);

        if (kid == null)
        {
            return null;
        }


        // Search the list of JWKs for a JWK having the key ID.
        JWK jwk = findJwkByKid(options, keys, kid);

        // Sign using the JWK having the key ID.
        return signUsingJWK(options, payload, jwk);
    }


    private JWSAlgorithm determineSigningAlg(JoseGeneratorOptions options, List<JWK> keys)
    {
        // The algorithm specified by the '--signing-alg' option or by the 'alg'
        // parameter in the JWS header specified by one of the '--jws-header[-*]' options.
        // Inconsistency that might exist between the algorithms are checked later
        // in signUsingJWK().
        JWSAlgorithm alg = (options.signingAlg != null) ? options.signingAlg
                         : ((mJwsHeader != null) ? mJwsHeader.getAlgorithm() : null);

        if (alg != null)
        {
            return alg;
        }

        // As a special fallback, only when all the JWKs in the JWK Set document have
        // the same algorithm, the algorithm is used. Otherwise, it's a fatal error.
        if (haveSameAlgorithm(keys) == false)
        {
            throw fatal(null, "The algorithm for signing must be specified by the "
                            + "'--signing-alg' option or other means");
        }

        alg = JWSAlgorithm.parse(keys.get(0).getAlgorithm().getName());
        verbose(options, "Using %s as the algorithm for signing because all the JWKs "
                       + "in the JWK Set document have the same algorithm.", alg.getName());

        if (Support.isSupportedJwsAlg(alg) == false)
        {
            throw fatal(null, "All the JWKs in the JWK Set document have the same algorithm "
                            + "(%s), but it is not supported.", alg.getName());
        }

        return alg;
    }


    private String signUsingJWKSetByAlg(
            JoseGeneratorOptions options, byte[] payload, List<JWK> keys, JWSAlgorithm alg) throws JOSEException
    {
        JWK selectedJwk = null;

        for (JWK jwk : keys)
        {
            if (jwk == null)
            {
                continue;
            }

            if (jwk.getAlgorithm() == null)
            {
                continue;
            }

            String name = jwk.getAlgorithm().getName();

            if (name == null)
            {
                continue;
            }

            if (name.equals(alg.getName()) == false)
            {
                continue;
            }

            if (jwk.getKeyID() != null)
            {
                selectedJwk = jwk;
                break;
            }

            selectedJwk = jwk;

            // selectedJwk has 'alg' but does not have 'kid'.
            // Continue the loop to find a JWK that may have both 'alg' and 'kid'.
        }

        // If no JWK has the algorithm.
        if (selectedJwk == null)
        {
            // Give up selecting a JWK by the signing algorithm.
            return null;
        }

        if (selectedJwk.getKeyID() != null)
        {
            // Check if the JWK Set document has multiple JWKs having the same key ID.
            if (haveDuplicateKid(keys, selectedJwk.getKeyID()))
            {
                throw fatal(null, "The JWK Set document contains multiple JWKs that have the same key ID (%s).",
                        selectedJwk.getKeyID());
            }
        }

        // Sign using the JWK.
        return signUsingJWK(options, payload, selectedJwk);
    }


    private JWK findJwkByKid(JoseGeneratorOptions options, List<JWK> keys, String kid)
    {
        JWK matchedJwk = null;

        for (JWK jwk : keys)
        {
            if (jwk == null)
            {
                continue;
            }

            if (kid.equals(jwk.getKeyID()))
            {
                if (matchedJwk != null)
                {
                    throw fatal(null, "The JWK Set document contains JWKs with the same key ID (%s).", kid);
                }

                matchedJwk = jwk;
            }
        }

        if (matchedJwk == null)
        {
            throw fatal(null, "The JWK Set document does not contain a JWK having the key ID (%s).", kid);
        }

        verbose(options, "A JWK having the key ID (%s) was found in the JWK Set document.", kid);

        return matchedJwk;
    }


    private boolean haveSameAlgorithm(List<JWK> keys)
    {
        String alg = null;

        for (JWK jwk : keys)
        {
            if (jwk == null)
            {
                return false;
            }

            if (jwk.getAlgorithm() == null)
            {
                return false;
            }

            String name = jwk.getAlgorithm().getName();

            if (name == null)
            {
                return false;
            }

            if (alg == null)
            {
                alg = name;
                continue;
            }

            if (alg.equals(name) == false)
            {
                return false;
            }
        }

        return (alg != null);
    }


    private boolean haveDuplicateKid(List<JWK> keys, String kid)
    {
        boolean found = false;

        for (JWK jwk : keys)
        {
            if (jwk == null || jwk.getKeyID() == null || jwk.getKeyID().equals(kid) == false)
            {
                continue;
            }

            if (found)
            {
                // Duplicate
                return true;
            }

            found = true;
        }

        // Not duplicate.
        return false;
    }


    private String signUsingJWKSetByKty(
            JoseGeneratorOptions options, byte[] payload, JWKSet jwks, JWSAlgorithm alg) throws JOSEException
    {
        // The key type for the algorithm.
        KeyType kty = KeyType.forAlgorithm(alg);

        // Select JWKs that has the key type and a key ID.
        // (TODO: minKeySize() should be used, too)
        List<JWK> matched = new JWKSelector(new JWKMatcher.Builder()
                .keyType(kty).hasKeyID(true).build()).select(jwks);

        if (matched == null || matched.size() == 0)
        {
            // Try to select JWKs again without the requirement for a key ID.
            matched = new JWKSelector(new JWKMatcher.Builder()
                    .keyType(kty).hasKeyID(false).build()).select(jwks);
        }

        if (matched == null || matched.size() == 0)
        {
            throw fatal(null, "The JWK Set document does not have any appropriate JWK for the algorithm (%s)",
                    alg.getName());
        }

        // Use the first JWK among the matched JWKs.
        return signUsingJWK(options, payload, matched.get(0));
    }


    private JWSObject createJwsObject(JWSAlgorithm algorithm, String keyId, Object content)
    {
        JWSHeader header = (mJwsHeader != null) ? mJwsHeader
                         : new JWSHeader.Builder(algorithm).keyID(keyId).build();
        Payload payload  = createPayload(content);

        return new JWSObject(header, payload);
    }


    private Payload createPayload(Object content)
    {
        if (content instanceof byte[])
        {
            return new Payload((byte[])content);
        }

        if (content instanceof String)
        {
            return new Payload((String)content);
        }

        return new Payload(content.toString());
    }


    private String encrypt(JoseGeneratorOptions options, byte[] payload)
    {
        verbose(options, "Encrypting.");

        // TODO
        throw fatal(null, "Encryption is not supported. (under development)");
    }


    private String unsecure(JoseGeneratorOptions options, byte[] payload)
    {
        verbose(options, "Creating an unsecured JWS.");

        return String.format("%s.%s.",
                UNSECURED_JWS_HEADER, Base64URL.encode(payload).toString());
    }


    private void verbose(JoseGeneratorOptions options, String format, Object... args)
    {
        if (options.verbose == false)
        {
            return;
        }

        PrintStream err = getStandardError();
        if (err == null)
        {
            return;
        }

        err.print("# ");
        err.format(format, args);
        err.println();
        err.flush();
    }


    private RuntimeException fatal(Throwable cause, String format, Object... args)
    {
        String message = String.format(format, args);

        PrintStream err = getStandardError();

        if (err != null)
        {
            if (cause != null)
            {
                cause.printStackTrace(err);
            }

            err.println(message);
        }

        if (cause != null)
        {
            return new RuntimeException(message, cause);
        }
        else
        {
            return new RuntimeException(message);
        }
    }
}
