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


import com.google.devtools.common.options.Converter;
import com.google.devtools.common.options.OptionsParsingException;


public abstract class BaseConverter<T> implements Converter<T>
{
    private final String mDescription;


    protected BaseConverter(String description)
    {
        mDescription = description;
    }


    @Override
    public T convert(String input) throws OptionsParsingException
    {
        try
        {
            // Convert the string to an instance of type T.
            return doConvert(input);
        }
        catch (OptionsParsingException e)
        {
            // Re-throw the exception without wrapping.
            throw e;
        }
        catch (Exception e)
        {
            throw new OptionsParsingException(
                String.format("Failed to parse '%s' as %s.", input, mDescription), e);
        }
    }


    @Override
    public String getTypeDescription()
    {
        return mDescription;
    }


    public abstract T doConvert(String input) throws Exception;
}
