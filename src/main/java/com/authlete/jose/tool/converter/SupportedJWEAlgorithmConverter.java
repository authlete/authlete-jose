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
package com.authlete.jose.tool.converter;


import com.authlete.jose.tool.Support;
import com.google.devtools.common.options.OptionsParsingException;
import com.nimbusds.jose.JWEAlgorithm;


public class SupportedJWEAlgorithmConverter extends JWEAlgorithmConverter
{
    @Override
    public JWEAlgorithm doConvert(String input) throws Exception
    {
        // Convert the string into a JWEAlgorithm instance.
        JWEAlgorithm alg = super.doConvert(input);

        // If the algorithm is supported.
        if (Support.isSupportedJweAlg(alg))
        {
            return alg;
        }

        String message = String.format("'%s' is not supported as a JWE algorithm.", input);

        throw new OptionsParsingException(message);
    }
}
