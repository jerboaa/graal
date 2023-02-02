/*
 * Copyright (c) 2020, 2020, Oracle and/or its affiliates. All rights reserved.
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
package com.oracle.svm.core.reflect.target;

import org.graalvm.nativeimage.ImageSingletons;

import com.oracle.svm.core.annotate.Substitute;
import com.oracle.svm.core.annotate.TargetClass;
import com.oracle.svm.core.annotate.TargetElement;
import com.oracle.svm.core.jdk.JDK19OrEarlier;
import com.oracle.svm.core.jdk.JDK20OrLater;
import com.oracle.svm.core.reflect.serialize.SerializationRegistry;

@TargetClass(className = "jdk.internal.reflect.AccessorGenerator")
public final class Target_jdk_internal_reflect_AccessorGenerator {
}

@TargetClass(className = "jdk.internal.reflect.MethodAccessorGenerator")
final class Target_jdk_internal_reflect_MethodAccessorGenerator {

    @Substitute
    @TargetElement(onlyWith = JDK20OrLater.class)
    public Target_jdk_internal_reflect_SerializationConstructorAccessorImpl generateSerializationConstructor(Class<?> declaringClass,
                    @SuppressWarnings("unused") Class<?>[] parameterTypes,
                    @SuppressWarnings("unused") int modifiers,
                    Class<?> targetConstructorClass) {
        return generateSerializationConstructor(declaringClass, parameterTypes, null, modifiers, targetConstructorClass);
    }

    @SuppressWarnings("static-method")
    @Substitute
    @TargetElement(onlyWith = JDK19OrEarlier.class)
    public Target_jdk_internal_reflect_SerializationConstructorAccessorImpl generateSerializationConstructor(Class<?> declaringClass,
                    @SuppressWarnings("unused") Class<?>[] parameterTypes,
                    @SuppressWarnings("unused") Class<?>[] checkedExceptions,
                    @SuppressWarnings("unused") int modifiers,
                    Class<?> targetConstructorClass) {
        SerializationRegistry serializationRegistry = ImageSingletons.lookup(SerializationRegistry.class);
        Object constructorAccessor = serializationRegistry.getSerializationConstructorAccessor(declaringClass, targetConstructorClass);
        return (Target_jdk_internal_reflect_SerializationConstructorAccessorImpl) constructorAccessor;
    }
}

@TargetClass(className = "jdk.internal.reflect.SerializationConstructorAccessorImpl")
final class Target_jdk_internal_reflect_SerializationConstructorAccessorImpl {
}
