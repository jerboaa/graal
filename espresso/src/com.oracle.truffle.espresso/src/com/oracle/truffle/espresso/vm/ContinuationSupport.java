package com.oracle.truffle.espresso.vm;

import com.oracle.truffle.api.CompilerDirectives;
import com.oracle.truffle.api.nodes.ControlFlowException;
import com.oracle.truffle.espresso.impl.Method;
import com.oracle.truffle.espresso.meta.Meta;
import com.oracle.truffle.espresso.runtime.EspressoContext;
import com.oracle.truffle.espresso.runtime.staticobject.StaticObject;
import com.oracle.truffle.espresso.substitutions.Inject;
import com.oracle.truffle.espresso.substitutions.JavaType;

/**
 * Support code used for implementation
 * the {@link com.oracle.truffle.espresso.substitutions.Target_com_oracle_truffle_espresso_continuations_Continuation continuation intrinsics}.
 */
public class ContinuationSupport {
    /**
     * A host-side mirror of a guest-side {@code Continuation.FrameRecord} object. The data in a frame record is
     * trusted but may be accidentally nonsensical in case of user error, for instance resuming a continuation
     * generated with a different version of the program or VM to what we are running now.
     */
    public static final class HostFrameRecord {
        public final StaticObject[] pointers;
        public final long[] primitives;
        public final int sp;
        public final Method.MethodVersion methodVersion;
        public HostFrameRecord next;

        // TODO: Add an `Object reserved` field to hold tags when assertions are enabled.

        public HostFrameRecord(StaticObject[] pointers, long[] primitives, int sp, Method.MethodVersion methodVersion,
                               HostFrameRecord next) {
            this.pointers = pointers;
            this.primitives = primitives;
            this.sp = sp;
            this.methodVersion = methodVersion;
            this.next = next;
        }

        /**
         * Copies this single record into a newly allocated guest-side object that the guest can then serialize,
         * deserialize and resume. Does <i>not</i> set the {@code next} pointer.
         */
        public @JavaType(internalName = "Lcom/oracle/truffle/espresso/continuations/Continuation$FrameRecord;") StaticObject
        copyToGuest(Meta meta) {
            // We discard frame cookies here. As they are only used for the guest StackWalker API and the obsolete
            // SecurityManager implementation, this seems OK.

            // ptrs already contains StaticObjects, but we need to fill out the nulls and do the casts ourselves, otherwise
            // we get ClassCastExceptions.
            StaticObject[] convertedPtrs = new StaticObject[pointers.length];
            for (int i = 0; i < convertedPtrs.length; i++)
                convertedPtrs[i] = pointers[i] != null ? pointers[i] : StaticObject.NULL;

            var guestRecord = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord.allocateInstance();
            meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_init_.invokeDirect(
                    guestRecord,
                    // Host arrays are not guest arrays, so convert.
                    StaticObject.wrap(convertedPtrs, meta),
                    StaticObject.wrap(primitives, meta),
                    methodVersion.getMethod().makeMirror(meta),
                    sp
            );
            return guestRecord;
        }

        /**
         * Copies the <i>entire</i> linked list of frame records from a guest {@code Continuation} object (which
         * contains the head frame record pointer) to a linked list of host frame records.
         */
        public static HostFrameRecord copyFromGuest(
                @JavaType(internalName = "Lcom/oracle/truffle/espresso/continuations/Continuation;") StaticObject self,
                Meta meta,
                @Inject EspressoContext context
        ) {
            HostFrameRecord hostCursor = null;
            HostFrameRecord hostHead = null;
            StaticObject /* FrameRecord */ cursor = meta.com_oracle_truffle_espresso_continuations_Continuation_stackFrameHead.getObject(self);
            while (StaticObject.notNull(cursor)) {
                /* Object[] */
                StaticObject pointersGuest = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_pointers.getObject(cursor);
                /* long[] */
                StaticObject primitivesGuest = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_primitives.getObject(cursor);
                /* java.lang.reflect.Method */
                StaticObject methodGuest = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_method.getObject(cursor);
                int sp = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_sp.getInt(cursor);

                var language = context.getLanguage();

                StaticObject[] pointers = pointersGuest.unwrap(language);
                long[] primitives = primitivesGuest.unwrap(language);
                Method method = (Method) meta.HIDDEN_METHOD_KEY.getHiddenObject(methodGuest);

                var next = new HostFrameRecord(pointers, primitives, sp, method.getMethodVersion(), null);
                if (hostCursor != null)
                    hostCursor.next = next;
                if (hostHead == null)
                    hostHead = next;
                hostCursor = next;
                cursor = meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_next.getObject(cursor);
            }

            return hostHead;
        }


        //        @SuppressWarnings("unused")
        //        public void dumpStackToStdOut() {
        //            System.out.printf("Stack has %d frames\n", frames.size());
        //            for (int i = 0; i < frames.size(); i++) {
        //                MaterializedFrame frame = frames.get(i);
        //                Method.MethodVersion methodVersion = methodVersions.get(i);
        //                System.out.printf("[%d] %s.%s()\n", i, methodVersion.getDeclaringKlass().getExternalName(), methodVersion.getNameAsString());
        //                System.out.printf("Object refs:\n%s\n   Primitives: %s\n",
        //                        String.join(
        //                                "\n",
        //                                stream(frame.getIndexedLocals())
        //                                        .map(it -> {
        //                                            var obj = (StaticObject) it;
        //                                            if (obj != null) {
        //                                                return "   • " + obj.toVerboseString().replace("\n", "\n     ");
        //                                            }
        //                                            return "   null";
        //                                        })
        //                                        .toList()
        //                        ),
        //
        //                        String.join(
        //                                "  ",
        //                                stream(frame.getIndexedPrimitiveLocals())
        //                                        .mapToObj(it -> String.format("0x%x", it))
        //                                        .toList()
        //                        )
        //                );
        //            }
        //        }
    }

    /**
     * The exception thrown host-side to unwind the stack when a continuation pauses. Frame info is gathered up into
     * a linked list.
     */
    public static class Unwind extends ControlFlowException {
        public HostFrameRecord head = null;

        @CompilerDirectives.TruffleBoundary
        public StaticObject toGuest(Meta meta) {
            // Convert the linked list from host to guest.
            ContinuationSupport.HostFrameRecord cursor = head;
            StaticObject guestHead = null;
            StaticObject guestCursor = null;
            while (cursor != null) {
                var next = cursor.copyToGuest(meta);
                if (guestHead == null)
                    guestHead = next;
                if (guestCursor != null)
                    meta.com_oracle_truffle_espresso_continuations_Continuation_FrameRecord_next.setObject(guestCursor, next);
                guestCursor = next;
                cursor = cursor.next;
            }
            return guestHead;
        }
    }
}
