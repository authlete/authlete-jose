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


import com.google.devtools.common.options.OptionsParser;


class JoseGeneratorOptionsParser
{
    public JoseGeneratorOptions parse(String[] args)
    {
        // Create a new parser.
        OptionsParser parser =
                OptionsParser.newOptionsParser(JoseGeneratorOptions.class);

        // Parse the arguments.
        parser.parseAndExitUponError(args);

        // Get the result of parsing the arguments.
        JoseGeneratorOptions options =
                parser.getOptions(JoseGeneratorOptions.class);

        // Return the validated options.
        return options;
    }
}
