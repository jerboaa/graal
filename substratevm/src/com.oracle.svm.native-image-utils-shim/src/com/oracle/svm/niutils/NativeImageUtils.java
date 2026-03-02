/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.oracle.svm.niutils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class NativeImageUtils {

    private static String NAME = "native-image-utils";
    private static String EXTRACT_CMD = "extract-sbom";
    private static String EXECUTABLE_IMAGE_OPT = "image-path";

    private static void usageAndExit() {
        System.err.printf("Usage: %s %s --%s=<path/to/image%n", NAME, EXTRACT_CMD, EXECUTABLE_IMAGE_OPT);
        System.exit(1);
    }

    // Simple double dash '--' options parsing with required value, specified via '=' assignment
    private static Map<String, String> parseOptions(String[] args) throws OptionParsingException {
        Map<String, String> options = new HashMap<>();
        for (String arg : args) {
            if (arg.startsWith("--")) {
                String optionVal = arg.substring(2);
                int equalsIdx = optionVal.indexOf('=');
                if (equalsIdx == -1) {
                    throw new OptionParsingException("Illegal value for option " + arg);
                } else {
                    String opt = String.format("--%s", optionVal.substring(0, equalsIdx));
                    String optVal = optionVal.substring(equalsIdx + 1);
                    options.put(opt, optVal);
                }
            }
            // Skip any non-option arguments
        }
        return options;
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            usageAndExit();
        }
        Path exe = null;
        try {
            Map<String, String> opts = parseOptions(args);
            String imagePath = opts.get(String.format("--%s", EXECUTABLE_IMAGE_OPT));
            if (imagePath == null) {
                System.err.printf("--%s option missing", EXECUTABLE_IMAGE_OPT);
                usageAndExit();
            }
            exe = Path.of(imagePath);
            if (!Files.exists(exe)) {
                System.err.println("Image path does not exist or is not readable: " + exe);
                usageAndExit();
            }
        } catch (OptionParsingException e) {
            System.err.println(e.getMessage());
            usageAndExit();
        }
        SbomExtractLibrary.extractSbom(exe);
    }

}
