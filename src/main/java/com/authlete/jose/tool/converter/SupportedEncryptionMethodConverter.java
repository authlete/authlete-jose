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
import com.nimbusds.jose.EncryptionMethod;


public class SupportedEncryptionMethodConverter extends EncryptionMethodConverter
{
    @Override
    public EncryptionMethod doConvert(String input) throws Exception
    {
        // Convert the string into an EncryptionMethod instance.
        EncryptionMethod enc = super.doConvert(input);

        // If the method is supported.
        if (Support.isSupportedJweEnc(enc))
        {
            return enc;
        }

        String message = String.format("'%s' is not supported as an encryption method.", input);

        throw new OptionsParsingException(message);
    }
}
