/*
 * Copyright (c) 2019, 2021, Oracle and/or its affiliates. All rights reserved.
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
package org.graalvm.compiler.hotspot.amd64;

import static org.graalvm.compiler.hotspot.meta.HotSpotForeignCallDescriptor.Reexecutability.REEXECUTABLE;
import static org.graalvm.compiler.hotspot.meta.HotSpotForeignCallDescriptor.Transition.LEAF;
import static org.graalvm.compiler.hotspot.meta.HotSpotForeignCallsProviderImpl.NO_LOCATIONS;
import static org.graalvm.compiler.replacements.ArrayIndexOf.NONE;
import static org.graalvm.compiler.replacements.ArrayIndexOf.S1;
import static org.graalvm.compiler.replacements.ArrayIndexOf.S2;
import static org.graalvm.compiler.replacements.ArrayIndexOf.S4;

import org.graalvm.compiler.api.replacements.Snippet;
import org.graalvm.compiler.core.common.spi.ForeignCallDescriptor;
import org.graalvm.compiler.debug.GraalError;
import org.graalvm.compiler.hotspot.HotSpotForeignCallLinkage;
import org.graalvm.compiler.hotspot.meta.HotSpotForeignCallDescriptor;
import org.graalvm.compiler.hotspot.meta.HotSpotProviders;
import org.graalvm.compiler.hotspot.stubs.SnippetStub;
import org.graalvm.compiler.lir.amd64.AMD64ArrayEqualsOp;
import org.graalvm.compiler.nodes.ValueNode;
import org.graalvm.compiler.options.OptionValues;
import org.graalvm.compiler.replacements.StrideUtil;
import org.graalvm.compiler.replacements.amd64.AMD64ArrayRegionEqualsWithMaskNode;

import jdk.vm.ci.meta.JavaKind;

public final class AMD64ArrayEqualsWithMaskStub extends SnippetStub {

    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S1_S1_S1 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS1S1S1", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);
    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S1_S2_S1 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS1S2S1", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);
    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S1_S2_S2 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS1S2S2", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);
    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S2_S1_S1 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS2S1S1", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);
    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S2_S2_S1 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS2S2S1", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);
    public static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_B_S2_S2_S2 = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsBS2S2S2", boolean.class, byte[].class, long.class, byte[].class, long.class, byte[].class, int.class);

    private static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_C = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsC", boolean.class, char[].class, long.class, char[].class, long.class, char[].class, int.class);

    private static final HotSpotForeignCallDescriptor STUB_REGION_EQUALS_GENERIC = new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                    "arrayRegionEqualsGeneric", boolean.class, Object.class, long.class, Object.class, long.class, byte[].class, int.class, int.class);

    private static HotSpotForeignCallDescriptor foreignCallDescriptor(String name) {
        return new HotSpotForeignCallDescriptor(LEAF, REEXECUTABLE, NO_LOCATIONS,
                        name, boolean.class, Object.class, long.class, Object.class, long.class, byte[].class, int.class);
    }

    /**
     * CAUTION: the ordering here is important: entries 0-9 must match the indices generated by
     * {@link org.graalvm.compiler.replacements.StrideUtil#getDirectStubCallIndex(ValueNode, JavaKind, JavaKind)}.
     *
     * @see #getStub(AMD64ArrayRegionEqualsWithMaskNode, AMD64HotSpotLIRGenerator)
     */
    public static final HotSpotForeignCallDescriptor[] STUBS = {
                    foreignCallDescriptor("arrayRegionEqualsS1S1"),
                    foreignCallDescriptor("arrayRegionEqualsS1S2"),
                    foreignCallDescriptor("arrayRegionEqualsS1S4"),
                    foreignCallDescriptor("arrayRegionEqualsS2S1"),
                    foreignCallDescriptor("arrayRegionEqualsS2S2"),
                    foreignCallDescriptor("arrayRegionEqualsS2S4"),
                    foreignCallDescriptor("arrayRegionEqualsS4S1"),
                    foreignCallDescriptor("arrayRegionEqualsS4S2"),
                    foreignCallDescriptor("arrayRegionEqualsS4S4"),

                    STUB_REGION_EQUALS_GENERIC,

                    STUB_REGION_EQUALS_B_S1_S1_S1,
                    STUB_REGION_EQUALS_B_S1_S2_S1,
                    STUB_REGION_EQUALS_B_S1_S2_S2,
                    STUB_REGION_EQUALS_B_S2_S1_S1,
                    STUB_REGION_EQUALS_B_S2_S2_S1,
                    STUB_REGION_EQUALS_B_S2_S2_S2,

                    STUB_REGION_EQUALS_C,
    };

    public static HotSpotForeignCallDescriptor getStub(AMD64ArrayRegionEqualsWithMaskNode node, AMD64HotSpotLIRGenerator gen) {
        JavaKind strideA = node.getStrideA();
        JavaKind strideB = node.getStrideB();
        JavaKind strideM = node.getStrideMask();
        ValueNode length = node.getLength();
        int directStubCallIndex = node.getDirectStubCallIndex();
        GraalError.guarantee(-1 <= directStubCallIndex && directStubCallIndex < 9, "invalid direct stub call index");
        if (directStubCallIndex >= 0 && length.isJavaConstant() &&
                        AMD64ArrayEqualsOp.canGenerateConstantLengthCompare(gen.target(),
                                        StrideUtil.getStrideA(directStubCallIndex),
                                        StrideUtil.getStrideB(directStubCallIndex), length.asJavaConstant().asInt(), gen.getMaxVectorSize())) {
            // Yield constant-length arrays comparison assembly
            return null;
        }
        switch (node.getArrayKind()) {
            case Byte:
                switch (strideA) {
                    case Byte:
                        switch (strideB) {
                            case Byte:
                                GraalError.guarantee(strideM == S1, "mask stride must match strideA and strideB");
                                return STUB_REGION_EQUALS_B_S1_S1_S1;
                            case Char:
                                switch (strideM) {
                                    case Byte:
                                        return STUB_REGION_EQUALS_B_S1_S2_S1;
                                    case Char:
                                        return STUB_REGION_EQUALS_B_S1_S2_S2;
                                    default:
                                        throw GraalError.shouldNotReachHere();
                                }
                            default:
                                throw GraalError.shouldNotReachHere();
                        }
                    case Char:
                        switch (strideB) {
                            case Byte:
                                GraalError.guarantee(strideM == S1, "mask stride must match strideA and strideB");
                                return STUB_REGION_EQUALS_B_S2_S1_S1;
                            case Char:
                                switch (strideM) {
                                    case Byte:
                                        return STUB_REGION_EQUALS_B_S2_S2_S1;
                                    case Char:
                                        return STUB_REGION_EQUALS_B_S2_S2_S2;
                                    default:
                                        throw GraalError.shouldNotReachHere();
                                }
                            default:
                                throw GraalError.shouldNotReachHere();
                        }
                    default:
                        throw GraalError.shouldNotReachHere();
                }
            case Char:
                GraalError.guarantee(strideA == S2 && strideB == S2 && strideM == S2, "only stride2 allowed for char arrays");
                return STUB_REGION_EQUALS_C;
            case Void:
                return directStubCallIndex < 0 ? STUB_REGION_EQUALS_GENERIC : STUBS[directStubCallIndex];
            default:
                throw GraalError.shouldNotReachHere();
        }
    }

    public AMD64ArrayEqualsWithMaskStub(ForeignCallDescriptor foreignCallDescriptor, OptionValues options, HotSpotProviders providers, HotSpotForeignCallLinkage linkage) {
        super(foreignCallDescriptor.getName(), options, providers, linkage);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS1S1S1(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S1, S1, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS1S2S1(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S1, S2, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS1S2S2(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S1, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS2S1S1(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S2, S1, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS2S2S1(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S2, S2, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsBS2S2S2(byte[] arrayA, long offsetA, byte[] arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S1, S2, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsC(char[] arrayA, long offsetA, char[] arrayB, long offsetB, char[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(S2, S2, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS1S1(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S1, S1, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS1S2(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S1, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS1S4(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S1, S4, S4, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS2S1(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S2, S1, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS2S2(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S2, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS2S4(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S2, S4, S4, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS4S1(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S4, S1, S1, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS4S2(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S4, S2, S2, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsS4S4(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(NONE, S4, S4, S4, arrayA, offsetA, arrayB, offsetB, mask, length);
    }

    @Snippet
    private static boolean arrayRegionEqualsGeneric(Object arrayA, long offsetA, Object arrayB, long offsetB, byte[] mask, int length, int stride) {
        return AMD64ArrayRegionEqualsWithMaskNode.regionEquals(arrayA, offsetA, arrayB, offsetB, mask, length, stride);
    }
}
