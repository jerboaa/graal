/*
 * Copyright (c) 2017, 2017, Oracle and/or its affiliates. All rights reserved.
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
package com.oracle.svm.hosted.jni;

import java.util.Arrays;
import java.util.List;

import org.graalvm.nativeimage.hosted.Feature;

import com.oracle.svm.core.jni.JNIRuntimeAccess;
import com.oracle.svm.core.jni.access.JNIAccessibleMethod;
import com.oracle.svm.hosted.FeatureImpl.DuringSetupAccessImpl;

/**
 * Responsible for generating JNI call wrappers for Java-to-native and native-to-Java invocations.
 *
 * <p>
 * Java-to-native call wrappers are created by {@link JNINativeCallWrapperSubstitutionProcessor}. It
 * creates a {@link JNINativeCallWrapperMethod} for each Java method that is declared with the
 * {@code native} keyword and that was registered via {@link JNIRuntimeAccess} to be accessible via
 * JNI at runtime. The method provides a graph that performs the native code invocation. This graph
 * is visible to the analysis.
 * </p>
 *
 * <p>
 * Native-to-Java call wrappers are generated by {@link JNIAccessFeature} as follows:
 * <ol>
 * <li>A {@link JNICallTrampolineMethod} exists for each way how a Java method can be invoked
 * (regular--including static--, and nonvirtual) and variant of passing arguments via JNI (varargs,
 * array, va_list), and implements the JNI {@code Call{Static,Nonvirtual}?<ReturnKind>Method{V,A}?}
 * functions, e.g. {@code CallIntMethod} or {@code CallNonvirtualObjectMethodA}. These trampolines
 * dispatch to the {@link JNIJavaCallVariantWrapperMethod} corresponding to the call.</li>
 * <li>{@link JNIJavaCallVariantWrapperMethod}s are generated so that for each method which can be
 * called via JNI and for each call variant, there exists a wrapper method which is compatible with
 * the called method's signature. Each wrapper method extracts its arguments according to its call
 * variant and passes them to a {@link JNIJavaCallWrapperMethod}.</li>
 * <li>A {@link JNIJavaCallWrapperMethod} for a specific signature resolves object handles in its
 * arguments (if any) and calls the specific Java method either by dynamic dispatch via an object's
 * vtable or via a function pointer for static or nonvirtual calls.<br/>
 * Separating call-variant wrappers and call wrappers significantly reduces code size because
 * call-variant wrappers can be made to be compatible to more different signatures than call
 * wrappers could, and each target signature requires providing three to six (for nonvirtual calls)
 * compatible call variant wrappers.</li>
 * <li>All dispatching is done via a {@code jmethodID}, which native code passes to the JNI call
 * functions and which is actually a reference to a {@link JNIAccessibleMethod} object containing
 * the function pointers for the wrapper methods and the target method and the vtable index.</li>
 * </ol>
 * </p>
 */
class JNICallWrapperFeature implements Feature {
    @Override
    public List<Class<? extends Feature>> getRequiredFeatures() {
        return Arrays.asList(JNIAccessFeature.class);
    }

    @Override
    public void duringSetup(DuringSetupAccess arg) {
        DuringSetupAccessImpl access = (DuringSetupAccessImpl) arg;
        access.registerNativeSubstitutionProcessor(new JNINativeCallWrapperSubstitutionProcessor(access));
    }
}
