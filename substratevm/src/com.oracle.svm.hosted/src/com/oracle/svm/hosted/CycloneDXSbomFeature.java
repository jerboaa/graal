/*
 * Copyright (c) 2026, 2026, Oracle and/or its affiliates. All rights reserved.
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

package com.oracle.svm.hosted;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPOutputStream;

import org.graalvm.nativeimage.ImageSingletons;
import org.graalvm.word.PointerBase;
import org.graalvm.word.UnsignedWord;

import com.oracle.svm.core.SubstrateOptions;
import com.oracle.svm.core.c.CGlobalData;
import com.oracle.svm.core.c.CGlobalDataFactory;
import com.oracle.svm.core.feature.AutomaticallyRegisteredFeature;
import com.oracle.svm.core.feature.InternalFeature;
import com.oracle.svm.core.util.VMError;
import com.oracle.svm.hosted.c.CGlobalDataFeature;

import jdk.graal.compiler.word.Word;

@AutomaticallyRegisteredFeature
public class CycloneDXSbomFeature implements InternalFeature {

    static class SBomValueWrapper {
        private final String value;

        private SBomValueWrapper(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

    }

    @Override
    public boolean isInConfiguration(IsInConfigurationAccess access) {
        String sbomOpt = SubstrateOptions.EnableSBOM.getValue();
        if (sbomOpt.startsWith("embed:")) {
            String embedValue = sbomOpt.substring(6 /* strip embed: */).trim();
            boolean valueIsFalse = "false".equals(embedValue);
            if (valueIsFalse) {
                return false;
            }
            // Register the value as an ImageSingleton
            ImageSingletons.add(SBomValueWrapper.class, new SBomValueWrapper(embedValue));
            return true;
        }
        System.err.println("Warning: --enable-sbom given without 'embed:' prefix! Feature disabled. Value was: " + sbomOpt);
        return false; // We only know about "embed:" for now.
    }

    @Override
    public void afterAnalysis(AfterAnalysisAccess access) {
        // Treat the sbom value as a path to an SBom file
        final byte[] sbomBytes = sbomBytes(Path.of(ImageSingletons.lookup(SBomValueWrapper.class).getValue()));
        CGlobalData<PointerBase> sbom = CGlobalDataFactory.createBytes(() -> {
            return sbomBytes;
        }, "sbom");
        CGlobalDataFeature.singleton().registerWithGlobalSymbol(sbom);
        int intSize = sbomBytes.length;
        UnsignedWord sizeVal = Word.unsigned(intSize);
        CGlobalData<PointerBase> sbomSizeVal = CGlobalDataFactory.createWord(sizeVal, "sbom_length");
        CGlobalDataFeature.singleton().registerWithGlobalSymbol(sbomSizeVal);
        System.out.println("SBOM bytes: " + intSize);
    }

    private static byte[] sbomBytes(Path sbomPath) {
        System.out.println("Path to sbom is: " + sbomPath);
        if (!Files.exists(sbomPath)) {
            String msg = String.format("Path to SBOM file %s does not exist or is not readable", sbomPath.toString());
            throw VMError.shouldNotReachHere(msg);
        }
        // FIXME: return a supplier of bytes
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (InputStream in = Files.newInputStream(sbomPath);
                        GZIPOutputStream zout = new GZIPOutputStream(bout)) {
            byte[] buf = new byte[1024 * 1024];
            int numbytes;
            while ((numbytes = in.read(buf)) != -1) {
                zout.write(buf, 0, numbytes);
            }
        } catch (IOException e) {
            throw VMError.shouldNotReachHere("gzip compress fail");
        }
        return bout.toByteArray();
    }

}
