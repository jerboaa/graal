/*
 * Copyright (c) 2021, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or
 * data (collectively the "Software"), free of charge and under any and all
 * copyright rights in the Software, and any and all patent rights owned or
 * freely licensable by each licensor hereunder covering either (i) the
 * unmodified Software as contributed to or provided by such licensor, or (ii)
 * the Larger Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at a
 * minimum a reference to the UPL must be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.oracle.truffle.api.dsl;

import java.util.logging.Level;

import com.oracle.truffle.api.TruffleLogger;
import com.oracle.truffle.api.nodes.Node;

/**
 * Allows tracing of calls to {@code execute} methods of a {@link Node}.
 * <p>
 * The methods declared in this interface are invoked by the code generated by Truffle DSL for nodes
 * which directly or indirectly implement this interface. All tracing methods are called only if
 * {@link #isTracingEnabled()} returns {@code true}.
 * <p>
 * Example:
 *
 * {@codesnippet com.oracle.truffle.api.dsl.ExecuteTracingSupportSnippets.Operation1Node}
 *
 * @since 21.3
 */
public interface ExecuteTracingSupport {

    /**
     * Invoked by the generated code to determine whether tracing is enabled. If tracing is
     * disabled, no other methods in this interface will be invoked.
     * 
     * @return {@code true} if tracing is enabled
     * @since 21.3
     */
    boolean isTracingEnabled();

    /**
     * Invoked by the generated {@code execute} methods before any {@link Specialization} is called,
     * but after all {@link NodeChildren} are evaluated. Called only if {@link #isTracingEnabled()}
     * returns {@code true}.
     * 
     * @param arguments the arguments of the specialization except the frame, if any
     * @since 21.3
     */
    default void traceOnEnter(@SuppressWarnings("unused") Object[] arguments) {
    }

    /**
     * Invoked by the generated {@code execute} methods when a {@link Specialization} returns
     * normally. Called only if {@link #isTracingEnabled()} returns {@code true}.
     *
     * @param returnValue the value returned by the specialization or {@code null} if the
     *            {@code execute} method is declared to return {@code void}
     * @since 21.3
     */
    default void traceOnReturn(@SuppressWarnings("unused") Object returnValue) {
    }

    /**
     * Invoked by the generated {@code execute} methods when a {@link Specialization} throws an
     * exception. Called only if {@link #isTracingEnabled()} returns {@code true}. Exceptions thrown
     * by child node invocations are not traced by the parent.
     *
     * @param t the exception thrown by the specialization
     * @since 21.3
     */
    default void traceOnException(@SuppressWarnings("unused") Throwable t) {
    }
}

@SuppressWarnings("unused")
class ExecuteTracingSupportSnippets {

    // BEGIN: com.oracle.truffle.api.dsl.ExecuteTracingSupportSnippets.Operation1Node
    abstract static class BaseNode extends Node implements ExecuteTracingSupport {

        static final TruffleLogger LOGGER = TruffleLogger.getLogger("id", "trace");

        @Override
        public boolean isTracingEnabled() {
            return LOGGER.isLoggable(Level.INFO);
        }

        @Override
        public void traceOnEnter(Object[] arguments) {
            // called before any execute method
        }

        @Override
        public void traceOnReturn(Object returnValue) {
            // called after any execute method if it returns normally
        }

        @Override
        public void traceOnException(Throwable t) {
            // called after any execute method which throws an exception
        }
    }

    abstract static class Operation1Node extends BaseNode {

        // any execute call would automatically be traced
        public abstract Object execute(int arg0, Object arg1);

        @Specialization
        int doInt(int a, int b) {
            return a + b;
        }
    }
    // END: com.oracle.truffle.api.dsl.ExecuteTracingSupportSnippets.Operation1Node
}
