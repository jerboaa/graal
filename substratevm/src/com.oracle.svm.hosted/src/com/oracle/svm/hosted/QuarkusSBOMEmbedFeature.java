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
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
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
public class QuarkusSBOMEmbedFeature implements InternalFeature {

    private static final String QUARKUS_FEATURE_CLASS_NAME = "io.quarkus.runner.Feature";

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
        // The feature is enabled only if one the following case holds:
        // --enable-sbom=embed:path-to-classpath-resource.json
        // It can be explicitly disabled by (e.g. to override an earlier option):
        // --enable-sbom=embed:false
        if (sbomOpt.startsWith("embed:")) {
            String embedValue = sbomOpt.substring(6 /* strip embed: */).trim();
            boolean valueIsFalse = "false".equals(embedValue);
            if (valueIsFalse) {
                return false;
            }
            // Register the value to the resource as an ImageSingleton
            ImageSingletons.add(SBomValueWrapper.class, new SBomValueWrapper(embedValue));
            return true;
        }
        return false; // We only know about "embed:" for now.
    }

    @Override
    public void afterAnalysis(AfterAnalysisAccess access) {
        // The SBOM is Quarkus provided and a resource on the app classloader in the quarkus jar
        String sbomResourceName = ImageSingletons.lookup(SBomValueWrapper.class).getValue();
        Class<?> quarkusFeatureClass = null;
        try {
            quarkusFeatureClass = Class.forName(QUARKUS_FEATURE_CLASS_NAME, true, access.getApplicationClassLoader());
        } catch (ClassNotFoundException e) {
            throw VMError.shouldNotReachHere("Quarkus Feature class required for SBOM embedding");
        }
        final SBomBytesRetriever retriever = new SBomBytesRetriever(quarkusFeatureClass, sbomResourceName);
        CGlobalData<PointerBase> sbom = CGlobalDataFactory.createBytes(retriever.sbomBytesSupplier(), "sbom");
        CGlobalDataFeature.singleton().registerWithGlobalSymbol(sbom);
        UnsignedWord sizeVal = Word.unsigned(retriever.getBytesLength());
        CGlobalData<PointerBase> sbomSizeVal = CGlobalDataFactory.createWord(sizeVal, "sbom_length");
        CGlobalDataFeature.singleton().registerWithGlobalSymbol(sbomSizeVal);
    }

    static class SBomBytesRetriever {

        private final Class<?> quarkusClass;
        private final String resourceName;
        private final AtomicBoolean bytesLenghAvailable = new AtomicBoolean(false);
        private volatile byte[] sbomBytes;

        SBomBytesRetriever(Class<?> quarkusClass, String resourceName) {
            this.quarkusClass = quarkusClass;
            this.resourceName = resourceName;
        }

        public Supplier<byte[]> sbomBytesSupplier() {
            return () -> {
                ensureSbomBytesRetrieved();
                return sbomBytes;
            };
        }

        private void ensureSbomBytesRetrieved() {
            if (!bytesLenghAvailable.getAndSet(true)) {
                final ByteArrayOutputStream bout = new ByteArrayOutputStream();
                readBytesToBout(bout);
                sbomBytes = bout.toByteArray();
            }
        }

        void readBytesToBout(ByteArrayOutputStream bout) {
            byte[] buf = new byte[1024];
            try (InputStream in = quarkusClass.getResourceAsStream(resourceName);
                            OutputStream out = (!resourceName.endsWith(".gz") ? new GZIPOutputStream(bout) : bout)) {
                if (in == null) {
                    String msg = String.format("Classpath resource to SBOM file %s does not exist", resourceName);
                    throw VMError.shouldNotReachHere(msg);
                }
                int numbytes;
                while ((numbytes = in.read(buf)) != -1) {
                    out.write(buf, 0, numbytes);
                }
            } catch (IOException e) {
                throw VMError.shouldNotReachHere("Unable to read SBOM bytes");
            }
        }

        public int getBytesLength() {
            ensureSbomBytesRetrieved();
            return sbomBytes.length;
        }
    }

}
