/*
 * Copyright (c) 2014, 2021, Oracle and/or its affiliates. All rights reserved.
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
package org.graalvm.compiler.replacements;

import static jdk.vm.ci.code.BytecodeFrame.UNKNOWN_BCI;
import static jdk.vm.ci.services.Services.IS_IN_NATIVE_IMAGE;
import static org.graalvm.compiler.nodes.CallTargetNode.InvokeKind.Static;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import org.graalvm.compiler.core.common.CompilationIdentifier;
import org.graalvm.compiler.core.common.type.Stamp;
import org.graalvm.compiler.core.common.type.StampFactory;
import org.graalvm.compiler.core.common.type.StampPair;
import org.graalvm.compiler.debug.DebugCloseable;
import org.graalvm.compiler.debug.DebugContext;
import org.graalvm.compiler.debug.GraalError;
import org.graalvm.compiler.graph.Graph;
import org.graalvm.compiler.graph.Node.ValueNumberable;
import org.graalvm.compiler.graph.NodeSourcePosition;
import org.graalvm.compiler.java.FrameStateBuilder;
import org.graalvm.compiler.java.GraphBuilderPhase;
import org.graalvm.compiler.nodes.AbstractBeginNode;
import org.graalvm.compiler.nodes.AbstractMergeNode;
import org.graalvm.compiler.nodes.BeginNode;
import org.graalvm.compiler.nodes.CallTargetNode;
import org.graalvm.compiler.nodes.CallTargetNode.InvokeKind;
import org.graalvm.compiler.nodes.EndNode;
import org.graalvm.compiler.nodes.FixedNode;
import org.graalvm.compiler.nodes.FixedWithNextNode;
import org.graalvm.compiler.nodes.IfNode;
import org.graalvm.compiler.nodes.InvokeNode;
import org.graalvm.compiler.nodes.InvokeWithExceptionNode;
import org.graalvm.compiler.nodes.LogicNode;
import org.graalvm.compiler.nodes.MergeNode;
import org.graalvm.compiler.nodes.NodeView;
import org.graalvm.compiler.nodes.ProfileData.BranchProbabilityData;
import org.graalvm.compiler.nodes.StateSplit;
import org.graalvm.compiler.nodes.StructuredGraph;
import org.graalvm.compiler.nodes.UnwindNode;
import org.graalvm.compiler.nodes.ValueNode;
import org.graalvm.compiler.nodes.WithExceptionNode;
import org.graalvm.compiler.nodes.calc.FloatingNode;
import org.graalvm.compiler.nodes.graphbuilderconf.GraphBuilderConfiguration;
import org.graalvm.compiler.nodes.graphbuilderconf.GraphBuilderConfiguration.Plugins;
import org.graalvm.compiler.nodes.graphbuilderconf.GraphBuilderTool;
import org.graalvm.compiler.nodes.java.ExceptionObjectNode;
import org.graalvm.compiler.nodes.java.MethodCallTargetNode;
import org.graalvm.compiler.nodes.spi.CoreProvidersDelegate;
import org.graalvm.compiler.nodes.type.StampTool;
import org.graalvm.compiler.phases.util.Providers;
import org.graalvm.compiler.word.WordTypes;

import jdk.vm.ci.code.BytecodeFrame;
import jdk.vm.ci.meta.JavaKind;
import jdk.vm.ci.meta.JavaType;
import jdk.vm.ci.meta.ResolvedJavaMethod;
import jdk.vm.ci.meta.ResolvedJavaType;
import jdk.vm.ci.meta.Signature;

/**
 * A utility for manually creating a graph. This will be expanded as necessary to support all
 * subsystems that employ manual graph creation (as opposed to {@linkplain GraphBuilderPhase
 * bytecode parsing} based graph creation).
 */
public abstract class GraphKit extends CoreProvidersDelegate implements GraphBuilderTool {

    protected final StructuredGraph graph;
    protected final WordTypes wordTypes;
    protected final GraphBuilderConfiguration.Plugins graphBuilderPlugins;
    protected FixedWithNextNode lastFixedNode;

    private final List<Structure> structures;

    protected abstract static class Structure {
    }

    public GraphKit(DebugContext debug, ResolvedJavaMethod stubMethod, Providers providers, WordTypes wordTypes, Plugins graphBuilderPlugins, CompilationIdentifier compilationId, String name,
                    boolean trackNodeSourcePosition, boolean recordInlinedMethods) {
        super(providers);
        StructuredGraph.Builder builder = new StructuredGraph.Builder(debug.getOptions(), debug).recordInlinedMethods(recordInlinedMethods).compilationId(compilationId).profileProvider(null);
        if (name != null) {
            builder.name(name);
        } else {
            builder.method(stubMethod);
        }
        this.graph = builder.build();
        graph.disableUnsafeAccessTracking();
        if (trackNodeSourcePosition) {
            graph.setTrackNodeSourcePosition();
        }
        if (graph.trackNodeSourcePosition()) {
            // Set up a default value that everything constructed by GraphKit will use.
            graph.withNodeSourcePosition(NodeSourcePosition.substitution(stubMethod));
        }
        this.wordTypes = wordTypes;
        this.graphBuilderPlugins = graphBuilderPlugins;
        this.lastFixedNode = graph.start();

        structures = new ArrayList<>();
        /*
         * Add a dummy element, so that the access of the last element never leads to an exception.
         */
        structures.add(new Structure() {
        });
    }

    @Override
    public StructuredGraph getGraph() {
        return graph;
    }

    @Override
    public boolean parsingIntrinsic() {
        return true;
    }

    /**
     * Ensures a floating node is added to or already present in the graph via {@link Graph#unique}.
     *
     * @return a node similar to {@code node} if one exists, otherwise {@code node}
     */
    public <T extends FloatingNode & ValueNumberable> T unique(T node) {
        return graph.unique(changeToWord(node));
    }

    public <T extends ValueNode> T add(T node) {
        return graph.add(changeToWord(node));
    }

    public <T extends ValueNode> T changeToWord(T node) {
        if (wordTypes != null && wordTypes.isWord(node)) {
            node.setStamp(wordTypes.getWordStamp(StampTool.typeOrNull(node)));
        }
        return node;
    }

    public Stamp wordStamp(ResolvedJavaType type) {
        assert wordTypes != null && wordTypes.isWord(type);
        return wordTypes.getWordStamp(type);
    }

    public final JavaKind asKind(JavaType type) {
        return wordTypes != null ? wordTypes.asKind(type) : type.getJavaKind();
    }

    @Override
    public <T extends ValueNode> T append(T node) {
        if (node.graph() != null) {
            return node;
        }
        T result = graph.addOrUniqueWithInputs(changeToWord(node));
        if (result instanceof FixedNode) {
            updateLastFixed((FixedNode) result);
        }
        return result;
    }

    private void updateLastFixed(FixedNode result) {
        assert lastFixedNode != null;
        assert result.predecessor() == null : "Expected the predecessor of " + result + " to be null, but it was " + result.predecessor();
        graph.addAfterFixed(lastFixedNode, result);
        if (result instanceof FixedWithNextNode) {
            lastFixedNode = (FixedWithNextNode) result;
        } else {
            lastFixedNode = null;
        }
    }

    public InvokeNode createInvoke(Class<?> declaringClass, String name, ValueNode... args) {
        return createInvoke(declaringClass, name, InvokeKind.Static, null, BytecodeFrame.UNKNOWN_BCI, args);
    }

    /**
     * Creates and appends an {@link InvokeNode} for a call to a given method with a given set of
     * arguments. The method is looked up via reflection based on the declaring class and name.
     *
     * @param declaringClass the class declaring the invoked method
     * @param name the name of the invoked method
     * @param args the arguments to the invocation
     */
    public InvokeNode createInvoke(Class<?> declaringClass, String name, InvokeKind invokeKind, FrameStateBuilder frameStateBuilder, int bci, ValueNode... args) {
        boolean isStatic = invokeKind == InvokeKind.Static;
        ResolvedJavaMethod method = findMethod(declaringClass, name, isStatic);
        return createInvoke(method, invokeKind, frameStateBuilder, bci, args);
    }

    public ResolvedJavaMethod findMethod(Class<?> declaringClass, String name, boolean isStatic) {
        ResolvedJavaType type = getMetaAccess().lookupJavaType(declaringClass);
        ResolvedJavaMethod method = null;
        for (ResolvedJavaMethod m : type.getDeclaredMethods()) {
            if (Modifier.isStatic(m.getModifiers()) == isStatic && m.getName().equals(name)) {
                assert method == null : "found more than one method in " + declaringClass + " named " + name;
                method = m;
            }
        }
        GraalError.guarantee(method != null, "Could not find %s.%s (%s)", declaringClass, name, isStatic ? "static" : "non-static");
        return method;
    }

    public ResolvedJavaMethod findMethod(Class<?> declaringClass, String name, Class<?>... parameterTypes) {
        try {
            Method m = declaringClass.getDeclaredMethod(name, parameterTypes);
            return getMetaAccess().lookupJavaMethod(m);
        } catch (NoSuchMethodException | SecurityException e) {
            throw new AssertionError(e);
        }
    }

    private NodeSourcePosition invokePosition(int invokeBci) {
        if (graph.trackNodeSourcePosition()) {
            NodeSourcePosition currentPosition = graph.currentNodeSourcePosition();
            assert currentPosition.getCaller() == null : "The GraphKit currentPosition should be a top level position.";
            return NodeSourcePosition.substitution(currentPosition.getMethod(), invokeBci);
        }
        return null;
    }

    /**
     * Creates and appends an {@link InvokeNode} for a call to a given method with a given set of
     * arguments.
     */
    @SuppressWarnings("try")
    public InvokeNode createInvoke(ResolvedJavaMethod method, InvokeKind invokeKind, FrameStateBuilder frameStateBuilder, int bci, ValueNode... args) {
        try (DebugCloseable context = graph.withNodeSourcePosition(invokePosition(bci))) {
            assert method.isStatic() == (invokeKind == InvokeKind.Static);
            Signature signature = method.getSignature();
            JavaType returnType = signature.getReturnType(null);
            assert checkArgs(method, args);
            StampPair returnStamp = graphBuilderPlugins.getOverridingStamp(this, returnType, false);
            if (returnStamp == null) {
                returnStamp = StampFactory.forDeclaredType(graph.getAssumptions(), returnType, false);
            }
            MethodCallTargetNode callTarget = graph.add(createMethodCallTarget(invokeKind, method, args, returnStamp, bci));
            InvokeNode invoke = append(new InvokeNode(callTarget, bci));

            pushForStateSplit(frameStateBuilder, bci, invoke);
            return invoke;
        }
    }

    private static void pushForStateSplit(FrameStateBuilder frameStateBuilder, int bci, StateSplit stateSplit) {
        if (frameStateBuilder != null) {
            JavaKind stackKind = stateSplit.asNode().getStackKind();
            if (stackKind != JavaKind.Void) {
                frameStateBuilder.push(stackKind, stateSplit.asNode());
            }
            stateSplit.setStateAfter(frameStateBuilder.create(bci, stateSplit));
            if (stackKind != JavaKind.Void) {
                frameStateBuilder.pop(stackKind);
            }
        }
    }

    public InvokeNode createIntrinsicInvoke(ResolvedJavaMethod method, ValueNode... args) {
        return createInvoke(method, Static, null, UNKNOWN_BCI, args);
    }

    @SuppressWarnings("try")
    public InvokeWithExceptionNode createInvokeWithExceptionAndUnwind(ResolvedJavaMethod method, InvokeKind invokeKind,
                    FrameStateBuilder frameStateBuilder, int invokeBci, ValueNode... args) {
        try (DebugCloseable context = graph.withNodeSourcePosition(invokePosition(invokeBci))) {
            InvokeWithExceptionNode result = startInvokeWithException(method, invokeKind, frameStateBuilder, invokeBci, args);
            exceptionPart();
            ExceptionObjectNode exception = exceptionObject();
            append(new UnwindNode(exception));
            endInvokeWithException();
            return result;
        }
    }

    @SuppressWarnings("try")
    public InvokeWithExceptionNode createInvokeWithExceptionAndUnwind(MethodCallTargetNode callTarget, FrameStateBuilder frameStateBuilder, int invokeBci) {
        try (DebugCloseable context = graph.withNodeSourcePosition(invokePosition(invokeBci))) {
            InvokeWithExceptionNode result = startInvokeWithException(callTarget, frameStateBuilder, invokeBci);
            exceptionPart();
            ExceptionObjectNode exception = exceptionObject();
            append(new UnwindNode(exception));
            endInvokeWithException();
            return result;
        }
    }

    protected MethodCallTargetNode createMethodCallTarget(InvokeKind invokeKind, ResolvedJavaMethod targetMethod, ValueNode[] args, StampPair returnStamp, @SuppressWarnings("unused") int bci) {
        return new MethodCallTargetNode(invokeKind, targetMethod, args, returnStamp, null);
    }

    /**
     * Determines if a given set of arguments is compatible with the signature of a given method.
     *
     * @return true if {@code args} are compatible with the signature if {@code method}
     * @throws AssertionError if {@code args} are not compatible with the signature if
     *             {@code method}
     */
    public boolean checkArgs(ResolvedJavaMethod method, ValueNode... args) {
        if (IS_IN_NATIVE_IMAGE) {
            // The dynamic lookup needed for this code is unsupported
            return true;
        }
        Signature signature = method.getSignature();
        boolean isStatic = method.isStatic();
        if (signature.getParameterCount(!isStatic) != args.length) {
            throw new AssertionError(graph + ": wrong number of arguments to " + method);
        }
        int argIndex = 0;
        if (!isStatic) {
            JavaKind expected = asKind(method.getDeclaringClass());
            JavaKind actual = args[argIndex++].stamp(NodeView.DEFAULT).getStackKind();
            assert expected == actual : graph + ": wrong kind of value for receiver argument of call to " + method + " [" + actual + " != " + expected + "]";
        }
        for (int i = 0; i != signature.getParameterCount(false); i++) {
            JavaKind expected = asKind(signature.getParameterType(i, method.getDeclaringClass())).getStackKind();
            JavaKind actual = args[argIndex++].stamp(NodeView.DEFAULT).getStackKind();
            if (expected != actual) {
                throw new AssertionError(graph + ": wrong kind of value for argument " + i + " of call to " + method + " [" + actual + " != " + expected + "]");
            }
        }
        return true;
    }

    protected void pushStructure(Structure structure) {
        structures.add(structure);
    }

    protected <T extends Structure> T getTopStructure(Class<T> expectedClass) {
        return expectedClass.cast(structures.get(structures.size() - 1));
    }

    protected void popStructure() {
        structures.remove(structures.size() - 1);
    }

    protected enum IfState {
        CONDITION,
        THEN_PART,
        ELSE_PART,
        FINISHED
    }

    static class IfStructure extends Structure {
        protected IfState state;
        protected FixedNode thenPart;
        protected FixedNode elsePart;
    }

    /**
     * Starts an if-block. This call can be followed by a call to {@link #thenPart} to start
     * emitting the code executed when the condition hold; and a call to {@link #elsePart} to start
     * emititng the code when the condition does not hold. It must be followed by a call to
     * {@link #endIf} to close the if-block.
     *
     * @param condition The condition for the if-block
     * @param profileData The estimated probability the condition is true
     * @return the created {@link IfNode}.
     */
    public IfNode startIf(LogicNode condition, BranchProbabilityData profileData) {
        AbstractBeginNode thenSuccessor = graph.add(new BeginNode());
        AbstractBeginNode elseSuccessor = graph.add(new BeginNode());
        IfNode node = append(new IfNode(condition, thenSuccessor, elseSuccessor, profileData));
        lastFixedNode = null;

        IfStructure s = new IfStructure();
        s.state = IfState.CONDITION;
        s.thenPart = thenSuccessor;
        s.elsePart = elseSuccessor;
        pushStructure(s);
        return node;
    }

    private IfStructure saveLastIfNode() {
        IfStructure s = getTopStructure(IfStructure.class);
        switch (s.state) {
            case CONDITION:
                assert lastFixedNode == null;
                break;
            case THEN_PART:
                s.thenPart = lastFixedNode;
                break;
            case ELSE_PART:
                s.elsePart = lastFixedNode;
                break;
            case FINISHED:
                assert false;
                break;
        }
        lastFixedNode = null;
        return s;
    }

    public void thenPart() {
        IfStructure s = saveLastIfNode();
        lastFixedNode = (FixedWithNextNode) s.thenPart;
        s.state = IfState.THEN_PART;
    }

    public void elsePart() {
        IfStructure s = saveLastIfNode();
        lastFixedNode = (FixedWithNextNode) s.elsePart;
        s.state = IfState.ELSE_PART;
    }

    /**
     * Ends an if block started with {@link #startIf(LogicNode, BranchProbabilityData)}.
     *
     * @return the created merge node, or {@code null} if no merge node was required (for example,
     *         when one part ended with a control sink).
     */
    public AbstractMergeNode endIf() {
        IfStructure s = saveLastIfNode();

        FixedWithNextNode thenPart = s.thenPart instanceof FixedWithNextNode ? (FixedWithNextNode) s.thenPart : null;
        FixedWithNextNode elsePart = s.elsePart instanceof FixedWithNextNode ? (FixedWithNextNode) s.elsePart : null;
        AbstractMergeNode merge = mergeControlSplitBranches(thenPart, elsePart);
        s.state = IfState.FINISHED;
        popStructure();
        return merge;
    }

    private AbstractMergeNode mergeControlSplitBranches(FixedWithNextNode x, FixedWithNextNode y) {
        AbstractMergeNode merge = null;
        if (x != null && y != null) {
            /* Both parts are alive, we need a real merge. */
            EndNode xEnd = graph.add(new EndNode());
            graph.addAfterFixed(x, xEnd);
            EndNode yEnd = graph.add(new EndNode());
            graph.addAfterFixed(y, yEnd);

            merge = graph.add(new MergeNode());
            merge.addForwardEnd(xEnd);
            merge.addForwardEnd(yEnd);

            lastFixedNode = merge;

        } else if (x != null) {
            /* y ended with a control sink, so we can continue with x. */
            lastFixedNode = x;

        } else if (y != null) {
            /* x ended with a control sink, so we can continue with y. */
            lastFixedNode = y;

        } else {
            /* Both parts ended with a control sink, so no nodes can be added afterwards. */
            assert lastFixedNode == null;
        }
        return merge;
    }

    protected static class WithExceptionStructure extends Structure {
        protected enum State {
            START,
            NO_EXCEPTION_EDGE,
            EXCEPTION_EDGE,
            FINISHED
        }

        protected State state;
        protected ExceptionObjectNode exceptionObject;
        protected FixedNode noExceptionEdge;
        protected FixedNode exceptionEdge;
    }

    public InvokeWithExceptionNode startInvokeWithException(ResolvedJavaMethod method, InvokeKind invokeKind,
                    FrameStateBuilder frameStateBuilder, int invokeBci, ValueNode... args) {

        assert method.isStatic() == (invokeKind == InvokeKind.Static);
        Signature signature = method.getSignature();
        JavaType returnType = signature.getReturnType(null);
        assert checkArgs(method, args);
        StampPair returnStamp = graphBuilderPlugins.getOverridingStamp(this, returnType, false);
        if (returnStamp == null) {
            returnStamp = StampFactory.forDeclaredType(graph.getAssumptions(), returnType, false);
        }
        MethodCallTargetNode callTarget = graph.add(createMethodCallTarget(invokeKind, method, args, returnStamp, invokeBci));
        return startInvokeWithException(callTarget, frameStateBuilder, invokeBci);
    }

    public InvokeWithExceptionNode startInvokeWithException(CallTargetNode callTarget, FrameStateBuilder frameStateBuilder, int invokeBci) {
        ExceptionObjectNode exceptionObject = createExceptionObjectNode(frameStateBuilder, invokeBci);
        InvokeWithExceptionNode invoke = append(new InvokeWithExceptionNode(callTarget, exceptionObject, invokeBci));
        return startWithException(invoke, exceptionObject, frameStateBuilder, invokeBci);
    }

    protected <T extends WithExceptionNode & StateSplit> T startWithException(T withException, ExceptionObjectNode exceptionObject, FrameStateBuilder frameStateBuilder, int bci) {
        AbstractBeginNode noExceptionEdge = graph.add(new BeginNode());
        withException.setNext(noExceptionEdge);
        pushForStateSplit(frameStateBuilder, bci, withException);
        lastFixedNode = null;

        WithExceptionStructure s = new WithExceptionStructure();
        s.state = WithExceptionStructure.State.START;
        s.noExceptionEdge = noExceptionEdge;
        s.exceptionEdge = exceptionObject;
        s.exceptionObject = exceptionObject;
        pushStructure(s);

        return withException;
    }

    protected ExceptionObjectNode createExceptionObjectNode(FrameStateBuilder frameStateBuilder, int exceptionEdgeBci) {
        ExceptionObjectNode exceptionObject = add(new ExceptionObjectNode(getMetaAccess()));
        setStateAfterException(frameStateBuilder, exceptionEdgeBci, exceptionObject, true);
        return exceptionObject;
    }

    protected void setStateAfterException(FrameStateBuilder frameStateBuilder, int exceptionEdgeBci, StateSplit exceptionObject, boolean rethrow) {
        if (frameStateBuilder != null) {
            FrameStateBuilder exceptionState = frameStateBuilder.copy();
            if (rethrow) {
                exceptionState.clearStack();
                exceptionState.setRethrowException(true);
            }
            exceptionState.push(JavaKind.Object, exceptionObject.asNode());
            exceptionObject.setStateAfter(exceptionState.create(exceptionEdgeBci, exceptionObject));
        }
    }

    private WithExceptionStructure saveLastWithExceptionNode() {
        WithExceptionStructure s = getTopStructure(WithExceptionStructure.class);
        switch (s.state) {
            case START:
                assert lastFixedNode == null;
                break;
            case NO_EXCEPTION_EDGE:
                s.noExceptionEdge = lastFixedNode;
                break;
            case EXCEPTION_EDGE:
                s.exceptionEdge = lastFixedNode;
                break;
            case FINISHED:
                assert false;
                break;
        }
        lastFixedNode = null;
        return s;
    }

    public void noExceptionPart() {
        WithExceptionStructure s = saveLastWithExceptionNode();
        lastFixedNode = (FixedWithNextNode) s.noExceptionEdge;
        s.state = WithExceptionStructure.State.NO_EXCEPTION_EDGE;
    }

    public void exceptionPart() {
        WithExceptionStructure s = saveLastWithExceptionNode();
        lastFixedNode = (FixedWithNextNode) s.exceptionEdge;
        s.state = WithExceptionStructure.State.EXCEPTION_EDGE;
    }

    public ExceptionObjectNode exceptionObject() {
        WithExceptionStructure s = getTopStructure(WithExceptionStructure.class);
        return s.exceptionObject;
    }

    /**
     * Finishes a control flow started with {@link #startInvokeWithException}. See
     * {@link #endWithException()}.
     */
    public AbstractMergeNode endInvokeWithException() {
        return endWithException();
    }

    /**
     * Finishes a control flow started with {@link #startWithException}. If necessary, creates a
     * merge of the non-exception and exception edges. The merge node is returned and the
     * non-exception edge is the first forward end of the merge, the exception edge is the second
     * forward end (relevant for phi nodes).
     */
    public AbstractMergeNode endWithException() {
        WithExceptionStructure s = saveLastWithExceptionNode();
        FixedWithNextNode noExceptionEdge = s.noExceptionEdge instanceof FixedWithNextNode ? (FixedWithNextNode) s.noExceptionEdge : null;
        FixedWithNextNode exceptionEdge = s.exceptionEdge instanceof FixedWithNextNode ? (FixedWithNextNode) s.exceptionEdge : null;
        AbstractMergeNode merge = mergeControlSplitBranches(noExceptionEdge, exceptionEdge);
        s.state = WithExceptionStructure.State.FINISHED;
        popStructure();
        return merge;
    }
}
