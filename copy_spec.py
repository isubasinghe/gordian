from typing import Optional
import source
import nip
from ghost_data_helpers import *


Mem = source.ExprVar(source.type_mem, source.ProgVarName('Mem'))


def htd_assigned() -> source.ExprVarT[nip.GuardVarName]:
    return g(source.ExprVar(source.type_bool, source.ProgVarName('HTD')))


def mem_assigned() -> source.ExprVarT[nip.GuardVarName]:
    return g(source.ExprVar(source.type_bool, source.ProgVarName('Mem')))


def pms_assigned() -> source.ExprVarT[nip.GuardVarName]:
    return g(source.ExprVar(source.type_bool, source.ProgVarName('PMS')))


def ghost_asserts_assigned() -> source.ExprVarT[nip.GuardVarName]:
    return g(source.ExprVar(source.type_bool, source.ProgVarName('GhostAssertions')))


def loop_count() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word64, source.ProgVarName('loop#2#count'))


def ring_handle() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word64, source.ProgVarName("ring___ptr_to_struct_ring_handle_C#v"))


def ring_handle_free_ring_offset(base: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(0))


def ring_handle_used_ring_offset(base: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(8))


def ring_mux_free_ring_loc() -> source.ExprT[source.ProgVarName]:
    return plus(rx_ring_mux(), u64(0))


def ring_mux_used_ring_loc() -> source.ExprT[source.ProgVarName]:
    return plus(rx_ring_mux(), u64(8))


def ring_cli_free_ring_loc() -> source.ExprT[source.ProgVarName]:
    return plus(rx_ring_cli(), u64(0))


def ring_cli_used_ring_loc() -> source.ExprT[source.ProgVarName]:
    return plus(rx_ring_cli(), u64(8))


def free_ring(base_name: Optional[str] = None) -> source.ExprVarT[source.ProgVarName]:
    default = "free_ring" if base_name is None else base_name
    return source.ProgVar(source.type_word64, source.ProgVarName(f"{default}___ptr_to_struct_ring_buffer_C#v"))


def ring(base_name: Optional[str] = None) -> source.ExprVarT[source.ProgVarName]:
    default = "ring" if base_name is None else base_name
    return source.ProgVar(source.type_word64, source.ProgVarName(f"{default}___ptr_to_struct_ring_buffer_C#v"))


def ptr() -> source.ExprVarT[source.ProgVarName]:
    return source.ProgVar(source.type_word64, source.ProgVarName('ptr___ptr_to_void#v'))


def ptrn(n: int) -> source.ExprVarT[source.ProgVarName]:
    return source.ProgVar(source.type_word64, source.ProgVarName(f'ptr{n}___ptr_to_void#v'))


def ring_head_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(0))


def ring_tail_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(4))


def ring_buffers_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(8))


def ring_sz_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(12296))


def ring_consumer_signalled_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(12300))


def buff_desc_phys_or_offset() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word64, source.ProgVarName("buffer___struct_buff_desc_C#v.phys_or_offset_C"))


def buff_desc_phys_or_offset_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(0))


def buff_desc_len() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word16, source.ProgVarName("buffer___struct_buff_desc_C#v.len_C"))


def buff_desc_len_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(8))


def buff_desc_cookie() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word64, source.ProgVarName("buffer___struct_buff_desc_C#v.cookie_C"))


def buff_desc_cookie_offset(base: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return plus(base, u64(16))


def local_ring() -> source.ExprVarT[source.ProgVarName]:
    return source.ExprVar(source.type_word64, source.ProgVarName('local_ring___ptr_to_struct_ring_buffer_C#v'))


def fits_u32(val: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return ule(val, u32(0xffff_ffff))


def fits_u64(val: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return ule(val, u64(0xffff_ffff_ffff_ffff))


def fits_pointer(val: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return ult(val, u64(0x0000_ffff_ffff_ffff))


def head_wf(head: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    assert head.typ == source.type_word32, f"{head.typ}"
    return ult(head, u32(512))


def tail_wf(tail: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return ult(tail, u32(512))


mux_addr_ghost = source.ExprVar(source.TypeBitVec(
    64), source.ProgVarName("mux_addr#ghost"))

mux_size_ghost = source.ExprVar(source.TypeBitVec(
    16), source.ProgVarName("mux_size#ghost"))

cli_addr_ghost = source.ExprVar(source.TypeBitVec(
    64), source.ProgVarName("cli_addr#ghost"))

copied_ghost = source.ExprVar(source.TypeBitVec(
    64), source.ProgVarName("copied#ghost"))

buff_phys_or_offset_ret = source.ExprVar(
    source.type_word64, source.CRetSpecialVar("c_ret.0"))
buff_phys_or_offset_ret.name.field_num = 0

buff_len_ret = source.ExprVar(
    source.type_word16, source.CRetSpecialVar("c_ret.0"))
buff_len_ret.name.field_num = 1


def distinct_all(ptr1: source.ExprT[source.ProgVarName],
                 ptr2: source.ExprT[source.ProgVarName],
                 ptr3: source.ExprT[source.ProgVarName],
                 ptr4: source.ExprT[source.ProgVarName],
                 ptr5: source.ExprT[source.ProgVarName],
                 ptr6: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return conjs(
        distinct(
            ptr1,
            2**16,
            ptr2,
            2**16
        ),

        distinct(
            ptr1,
            2**16,
            ptr3,
            2**16
        ),

        distinct(
            ptr1,
            2**16,
            ptr4,
            2**16
        ),

        distinct(
            ptr1,
            2**16,
            ptr5,
            2**16
        ),

        distinct(
            ptr1,
            2**16,
            ptr6,
            2**16
        ),

        distinct(
            ptr2,
            2**16,
            ptr3,
            2**16
        ),

        distinct(
            ptr2,
            2**16,
            ptr4,
            2**16
        ),

        distinct(
            ptr2,
            2**16,
            ptr5,
            2**16
        ),

        distinct(
            ptr2,
            2**16,
            ptr6,
            2**16
        ),

        distinct(
            ptr3,
            2**16,
            ptr4,
            2**16
        ),

        distinct(
            ptr3,
            2**16,
            ptr5,
            2**16
        ),

        distinct(
            ptr3,
            2**16,
            ptr6,
            2**16
        ),

        distinct(
            ptr4,
            2**16,
            ptr5,
            2**16
        ),

        distinct(
            ptr4,
            2**16,
            ptr6,
            2**16
        ),

        distinct(
            ptr5,
            2**16,
            ptr6,
            2**16
        ),

    )


def common_mem_wf(mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return conjs(
        fits_pointer(
            rx_ring_cli()
        ),
        fits_pointer(
            rx_ring_mux()
        ),
        fits_pointer(
            mem_acc(
                source.type_word64,
                ring_mux_free_ring_loc(),
                mem
            ),
        ),
        fits_pointer(
            mem_acc(
                source.type_word64,
                ring_mux_used_ring_loc(),
                mem
            ),
        ),
        ring_wf(
            mem_acc(
                source.type_word64,
                ring_mux_free_ring_loc(),
                mem
            ),
            mem
        ),
        ring_wf(
            mem_acc(
                source.type_word64,
                ring_mux_used_ring_loc(),
                mem
            ),
            mem
        ),

        ring_wf(
            mem_acc(
                source.type_word64,
                ring_cli_free_ring_loc(),
                mem
            ),
            mem
        ),
        ring_wf(
            mem_acc(
                source.type_word64,
                ring_cli_used_ring_loc(),
                mem
            ),
            mem
        ),

        distinct_all(
            rx_ring_mux(),
            rx_ring_cli(),
            mem_acc(
                source.type_word64,
                ring_mux_used_ring_loc(),
                mem
            ),
            mem_acc(
                source.type_word64,
                ring_mux_free_ring_loc(),
                mem
            ),

            mem_acc(
                source.type_word64,
                ring_cli_used_ring_loc(),
                mem
            ),

            mem_acc(
                source.type_word64,
                ring_cli_free_ring_loc(),
                mem
            ),
        ),
    )


def distinct(addr1: source.ExprT[source.ProgVarName], len1: int, addr2: source.ExprT[source.ProgVarName], len2: int) -> source.ExprT[source.ProgVarName]:
    return source.expr_or(
        conjs(
            ult(addr1, addr2),
            ult(
                plus(addr1, u64(len1)),
                addr2
            ),
        ),
        conjs(
            ult(addr2, addr1),
            ult(
                plus(addr2, u64(len2)),
                addr1
            )
        )
    )


def ring_wf(ring: source.ExprT[source.ProgVarName], mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    assert mem.typ == source.type_mem
    return conjs(
        fits_u32(
            plus(
                mem_acc(
                    source.type_word32,
                    ring_head_offset(ring),
                    mem
                ),
                u32(1)
            )
        ),
        head_wf(
            mem_acc(
                source.type_word32,
                ring_head_offset(ring),
                mem
            )
        ),
        tail_wf(
            ring_acc_tail(
                ring,
                mem
            )
        ),
        eq(
            mem_acc(
                source.type_word32,
                ring_sz_offset(ring),
                mem
            ),
            u32(512)
        ),
        fits_u32(
            plus(
                mem_acc(
                    source.type_word32,
                    ring_tail_offset(ring),
                    mem
                ),
                u32(1)
            )
        )
    )


def ring_empty_spec(ring_base: source.ExprT[source.ProgVarName], mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return eq(
        ring_acc_head(
            ring_base,
            mem
        ),
        ring_acc_tail(
            ring_base,
            mem
        )
    )


def ring_full_spec(ring_base: source.ExprT[source.ProgVarName],
                   mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return eq(
        mod(
            plus(
                mem_acc(
                    source.type_word32,
                    ring_head_offset(
                        ring_base
                    ),
                    mem
                ),
                u32(1)
            ),
            mem_acc(
                source.type_word32,
                ring_sz_offset(
                    ring_base
                ),
                mem
            ),
        ),
        mem_acc(
            source.type_word32,
            ring_tail_offset(
                ring_base
            ),
            mem
        )
    )


def ring_acc_head(ring: source.ExprT[source.ProgVarName], mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return mem_acc(
        source.type_word32,
        ring_head_offset(ring),
        mem
    )


def ring_acc_tail(ring: source.ExprT[source.ProgVarName], mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return mem_acc(
        source.type_word32,
        ring_tail_offset(ring),
        mem
    )


def ring_acc_sz(ring: source.ExprT[source.ProgVarName], mem: source.ExprVarT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return mem_acc(
        source.type_word32,
        ring_sz_offset(ring),
        mem
    )


def ring_loc_buffer_at_phys_or_offset(ring: source.ExprT[source.ProgVarName], index: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:

    return buff_desc_phys_or_offset_offset(
        plus(
            ring_buffers_offset(
                ring
            ),
            mul(
                ucast(
                    source.type_word64,
                    index
                ),
                u64(24)
            )
        )
    )


def ring_loc_buffer_at_len(ring: source.ExprT[source.ProgVarName], index: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return buff_desc_len_offset(
        plus(
            ring_buffers_offset(
                ring
            ),
            mul(
                ucast(
                    source.type_word64,
                    index
                ),
                u64(24)
            )
        )
    )


def ring_loc_buffer_at_cookie(ring: source.ExprT[source.ProgVarName], index: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return buff_desc_cookie_offset(
        plus(
            ring_buffers_offset(
                ring
            ),
            mul(
                ucast(
                    source.type_word64,
                    index
                ),
                u64(24)
            )
        )
    )


def dequeue_post(argring: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return conjs(
        eq(
            Mem,
            mem_upd(
                source.type_word32,
                ring_tail_offset(argring),
                mod(
                    plus(
                        ring_acc_tail(
                            argring,
                            arg(Mem)
                        ),
                        u32(1)
                    ),
                    ring_acc_sz(
                        argring,
                        arg(Mem)
                    ),
                ),
                arg(Mem)
            ),
        ),
        ring_wf(argring, Mem),
    )


def enqueue_post(argring: source.ExprT[source.ProgVarName]) -> source.ExprT[source.ProgVarName]:
    return conjs(
        ring_wf(argring, Mem),
        eq(
            Mem,
            mem_upd(
                source.type_word32,
                ring_head_offset(argring),
                mod(
                    plus(
                        mem_acc(
                            source.type_word32,
                            ring_head_offset(argring),
                            arg(Mem)
                        ),
                        u32(1)
                    ),
                    mem_acc(
                        source.type_word32,
                        ring_sz_offset(argring),
                        arg(Mem)
                    )
                ),
                mem_upd(
                    source.type_word64,
                    ring_loc_buffer_at_cookie(
                        argring,
                        ring_acc_head(
                            argring,
                            arg(Mem)
                        ),
                    ),
                    buff_desc_cookie(),
                    mem_upd(
                        source.type_word16,
                        ring_loc_buffer_at_len(
                            argring,
                            ring_acc_head(
                                argring,
                                arg(Mem)
                            )
                        ),
                        buff_desc_len(),
                        mem_upd(
                            source.type_word64,
                            ring_loc_buffer_at_phys_or_offset(
                                argring,
                                ring_acc_head(
                                    argring,
                                    arg(Mem)
                                )
                            ),
                            buff_desc_phys_or_offset(),
                            arg(Mem)
                        )
                    )
                )
            )

        )

    )


def rx_ring_mux() -> source.ExprT[source.ProgVarName]:
    return source.ExprFunction(source.type_word64, source.FunctionName("rx_ring_mux@global-symbol"), ())


def rx_ring_cli() -> source.ExprT[source.ProgVarName]:
    return source.ExprFunction(source.type_word64, source.FunctionName("rx_ring_cli@global-symbol"), ())


def cli_buffer_data_region() -> source.ExprT[source.ProgVarName]:
    return source.ExprFunction(source.type_word64, source.FunctionName("cli_buffer_data_region@global-symbol"), ())


def mux_buffer_data_region() -> source.ExprT[source.ProgVarName]:
    return source.ExprFunction(source.type_word64, source.FunctionName("mux_buffer_data_region@global-symbol"), ())


def truthy() -> source.ExprVarT[source.ProgVarName]:
    return ucharv('truthy')


functions_spec = {
    "tmp.init": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.assert": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(eq(arg(Mem), Mem)),
        loop_invariants={},
        loop_iterations={}
    ),
    # NOTE: not a specification
    # for a general memcpy.
    # Requires conditions on rings
    # this avoids quantifiers
    "tmp.memcpy": source.Ghost(
        precondition=conjs(
            common_mem_wf(arg(Mem)),
            eq(
                arg(copied_ghost),
                u64(0)
            ),
            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_cli_used_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)

            )),
            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_mux_free_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)
            )),
        ),
        postcondition=conjs(
            eq(arg(copied_ghost), u64(1)),
            eq(mux_addr_ghost, arg(mux_addr_ghost)),
            eq(cli_addr_ghost, arg(cli_addr_ghost)),
            eq(mux_size_ghost, arg(mux_size_ghost)),
            common_mem_wf(Mem),

            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_cli_used_ring_loc(),
                    Mem
                ),
                Mem
            )),
            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_mux_free_ring_loc(),
                    Mem
                ),
                Mem
            )),
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.dequeue": source.Ghost(
        precondition=conjs(
            ring_wf(arg(ring()), arg(Mem)),
            neq(
                ring_acc_head(
                    arg(ring()),
                    arg(Mem)
                ),
                ring_acc_tail(
                    arg(ring()),
                    arg(Mem)
                )
            )
        ),
        postcondition=conjs(
            dequeue_post(arg(ring()))
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.enqueue": source.Ghost(
        precondition=conjs(
            ring_wf(
                arg(ring()),
                arg(Mem)
            ),
            neq(
                mod(
                    plus(
                        ring_acc_head(
                            arg(ring()),
                            arg(Mem)
                        ),
                        u32(1)
                    ),
                    ring_acc_sz(
                        arg(ring()),
                        arg(Mem)
                    )
                ),
                ring_acc_tail(
                    arg(ring()),
                    arg(Mem)
                )
            )
        ),
        postcondition=conjs(
            ring_wf(arg(ring()), Mem),
            enqueue_post(arg(ring()))
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.enqueue_free": source.Ghost(
        precondition=conjs(
            eq(
                arg(buff_desc_phys_or_offset()),
                arg(mux_addr_ghost)
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16,
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            neq(
                mod(
                    plus(
                        ring_acc_head(
                            mem_acc(
                                source.type_word64,
                                ring_handle_free_ring_offset(
                                    arg(ring_handle()),
                                ),
                                arg(Mem)
                            ),
                            arg(Mem)
                        ),
                        u32(1)
                    ),
                    ring_acc_sz(
                        mem_acc(
                            source.type_word64,
                            ring_handle_free_ring_offset(
                                arg(ring_handle()),
                            ),
                            arg(Mem)
                        ),
                        arg(Mem)
                    ),
                ),
                ring_acc_tail(
                    mem_acc(
                        source.type_word64,
                        ring_handle_free_ring_offset(
                            arg(ring_handle()),
                        ),
                        arg(Mem)
                    ),
                    arg(Mem)
                ),
            ),
        ),
        postcondition=conjs(
            eq(
                mux_addr_ghost,
                u64(0)

            ),
            eq(
                arg(cli_addr_ghost),
                cli_addr_ghost
            ),
            eq(
                arg(mux_size_ghost),
                mux_size_ghost
            ),
            eq(
                arg(copied_ghost),
                copied_ghost
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                Mem
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                Mem
            ),
            enqueue_post(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                )
            )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.rx_return_inner_inner": source.Ghost(
        precondition=conjs(
            common_mem_wf(arg(Mem)),
            neg(ring_empty_spec(
                mem_acc(
                    source.type_word64,
                    ring_mux_used_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)
            )),
            neg(ring_empty_spec(
                mem_acc(
                    source.type_word64,
                    ring_cli_free_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)
            )),
            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_cli_used_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)

            )),
            neg(ring_full_spec(
                mem_acc(
                    source.type_word64,
                    ring_mux_free_ring_loc(),
                    arg(Mem)
                ),
                arg(Mem)
            )),
        ),
        postcondition=conjs(
            common_mem_wf(Mem),
            eq(
                copied_ghost,
                u64(1)
            ),
            eq(
                mux_addr_ghost,
                u64(0)
            ),
            eq(
                cli_addr_ghost,
                u64(0)
            )
        ),
        loop_invariants={
        },
        loop_iterations={
            lh('5'): source.LoopIterationGhost(
                pre_iter=source.expr_true,
                post_iter=source.expr_true
            )
        }

    ),
    "tmp.rx_return_inner": source.Ghost(
        precondition=conjs(
            common_mem_wf(arg(Mem))
        ),
        postcondition=conjs(
            common_mem_wf((Mem)),
        ),
        loop_invariants={
            lh('5'): conjs(
                mem_assigned(),
                pms_assigned(),
                htd_assigned(),
                ghost_asserts_assigned(),
                g(ucharv('enqueued')),
                common_mem_wf(Mem)
            )
        },
        loop_iterations={
            lh('5'): source.LoopIterationGhost(
                pre_iter=source.expr_true,
                post_iter=source.expr_true
            )
        }
    ),
    "tmp.notified": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={},
        loop_iterations={}
    ),
    # essentially ghost code to consume the ticket
    # for the client only
    "tmp.empty_consume": source.Ghost(
        precondition=conjs(
            neq(
                cli_addr_ghost,
                u64(0)
            )
        ),
        postcondition=conjs(
            eq(
                cli_addr_ghost,
                u64(0)
            ),
            eq(
                mux_addr_ghost,
                arg(mux_addr_ghost)
            ),
            eq(
                arg(mux_size_ghost),
                mux_size_ghost 
            ),
            eq(
                arg(copied_ghost),
                copied_ghost 
            ),
            common_mem_wf(Mem)
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.memcpy": source.Ghost(
        precondition=conjs(
            eq(
                arg(copied_ghost),
                u64(0)
            ),
            common_mem_wf(arg(Mem))
        ),
        postcondition=conjs(
            common_mem_wf(Mem),
            eq(
                copied_ghost,
                u64(1)
            )
        ),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.ring_full": source.Ghost(
        precondition=conjs(
            neq(mem_acc(source.type_word32, ring_sz_offset(
                arg(ring())), arg(Mem)), u32(0))
        ),
        postcondition=conjs(
            eq(u8ret,
               bv8eq(
                   mod(
                       plus(
                           mem_acc(source.type_word32, ring_head_offset(
                               arg(ring())), arg(Mem)),
                           u32(1)
                       ),
                       mem_acc(source.type_word32, ring_sz_offset(
                           arg(ring())), arg(Mem)),
                   ),
                   mem_acc(source.type_word32, ring_tail_offset(
                       arg(ring())), arg(Mem))
               )
               ),
            eq(arg(Mem), Mem)
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.ring_init": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.ring_size": source.Ghost(
        precondition=conjs(

            neq(mem_acc(source.type_word32, ring_sz_offset(
                arg(ring())), arg(Mem)), u32(0))
        ),
        postcondition=conjs(
            eq(u32ret,
               mod(
                   sub(
                       plus(
                           mem_acc(
                               source.type_word32,
                               ring_head_offset(arg(ring())),
                               arg(Mem)),
                           mem_acc(
                               source.type_word32,
                               ring_sz_offset(arg(ring())),
                               arg(Mem))
                       ),
                       mem_acc(
                           source.type_word32,
                           ring_tail_offset(arg(ring())),
                           arg(Mem)
                       )
                   ),
                   mem_acc(source.type_word32, ring_sz_offset(
                       arg(ring())), arg(Mem))
               )
               ),
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.cond": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(
            eq(
                mem_acc(
                    source.type_word32,
                    source.ExprFunction(
                        source.type_word64,
                        source.FunctionName('blah@global-symbol'),
                        ()
                    ),
                    Mem

                ),
                i32(45)
            )
        ),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.ring_empty": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(
            eq(arg(Mem), Mem),
            eq(
                u8ret,
                bv8eq(
                    ring_acc_head(
                        arg(ring()),
                        arg(Mem)
                    ),
                    ring_acc_tail(
                        arg(ring()),
                        arg(Mem)
                    )
                )
            )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.buffers_init": source.Ghost(
        precondition=conjs(
            neq(mem_acc(source.type_word32, ring_sz_offset(
                arg(free_ring())), arg(Mem)), u32(0)),
            ult(mem_acc(source.type_word32, ring_head_offset(
                arg(free_ring())), arg(Mem)), u32(512)),
            ult(arg(u32v('ring_size')), u32(1024))
        ),
        postcondition=conjs(),
        loop_invariants={
            lh('3'): conjs(
                g(i32v('i')),
                g(u32v('ring_size')),
                mem_assigned(),
                htd_assigned(),
                pms_assigned(),
                ghost_asserts_assigned(),
                conjs(
                    neq(mem_acc(source.type_word32, ring_sz_offset(
                        free_ring()), Mem), u32(0)),
                    ult(mem_acc(source.type_word32, ring_head_offset(
                        free_ring()), Mem), u32(512)),
                ),
                ult(i32v('i'), u32(1024))
            )
        },
        loop_iterations={
            lh('3'): source.LoopIterationGhost(
                pre_iter=source.expr_true,
                post_iter=source.expr_true
            )

        }
    ),
    "tmp.dequeue_free": source.Ghost(
        precondition=conjs(
            eq(
                arg(cli_addr_ghost),
                u64(0)
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(arg(ring_handle())),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            neg(
                ring_empty_spec(
                    mem_acc(
                        source.type_word64,
                        ring_handle_free_ring_offset(
                            arg(ring_handle())
                        ),
                        arg(Mem)
                    ),
                    arg(Mem)
                )
            ),
        ),
        postcondition=conjs(
            eq(
                plus(
                    mem_acc(
                        source.type_word64,
                        cli_buffer_data_region(),
                        Mem
                    ),
                    buff_phys_or_offset_ret
                ),
                cli_addr_ghost
            ),
            eq(
                arg(mux_addr_ghost),
                mux_addr_ghost
            ),
            eq(
                arg(mux_size_ghost),
                mux_size_ghost
            ),
            eq(
                arg(copied_ghost),
                copied_ghost
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                Mem
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    Mem
                ),
                Mem
            ),
            dequeue_post(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            )
        ),
        loop_invariants={},
        loop_iterations={}

    ),
    "tmp.assert": source.Ghost(
        precondition=source.expr_false,
        postcondition=source.expr_true,
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.assert_fits_pointer": source.Ghost(
        precondition=fits_pointer(arg(ptr())),
        postcondition=eq(Mem, arg(Mem)),
        loop_invariants={
        },
        loop_iterations={}
    ),
    "tmp.assert_ring_wf": source.Ghost(
        precondition=ring_wf(
            arg(ring()),
            arg(Mem)
        ),
        postcondition=eq(Mem, arg(Mem)),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.assert_ring_non_empty": source.Ghost(
        precondition=neg(
            ring_empty_spec(
                arg(ring()),
                arg(Mem)
            )
        ),
        postcondition=eq(Mem, arg(Mem)),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.assert_ring_full": source.Ghost(
        precondition=neg(
            ring_full_spec(
                arg(ring()),
                arg(Mem)
            )
        ),
        postcondition=eq(Mem, arg(Mem)),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.assert_ring_distinct": source.Ghost(
        precondition=conjs(
            distinct_all(
                arg(ptrn(1)),
                arg(ptrn(2)),
                arg(ptrn(3)),
                arg(ptrn(4)),
                arg(ptrn(5)),
                arg(ptrn(6)),
            )
        ),
        postcondition=eq(Mem, arg(Mem)),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.empty_consume": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.dequeue_used": source.Ghost(
        precondition=conjs(
            eq(
                arg(mux_addr_ghost),
                u64(0)
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(arg(ring_handle())),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            neg(
                ring_empty_spec(
                    mem_acc(
                        source.type_word64,
                        ring_handle_used_ring_offset(
                            arg(ring_handle())
                        ),
                        arg(Mem)
                    ),
                    arg(Mem)
                )
            ),
        ),
        postcondition=conjs(
            eq(
                plus(
                    mem_acc(
                        source.type_word64,
                        mux_buffer_data_region(),
                        Mem
                    ),
                    buff_phys_or_offset_ret
                ),
                mux_addr_ghost
            ),
            eq(
                mux_size_ghost,
                buff_len_ret
            ),

            eq(
                arg(copied_ghost),
                copied_ghost
            ),
            eq(
                arg(cli_addr_ghost),
                cli_addr_ghost
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                Mem
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    Mem
                ),
                Mem
            ),
            dequeue_post(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.enqueue_used": source.Ghost(
        precondition=conjs(
            eq(
                arg(buff_desc_phys_or_offset()),
                arg(cli_addr_ghost)
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16,
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                2**16
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle()),
                    ),
                    arg(Mem)
                ),
                arg(Mem)
            ),
            neq(
                mod(
                    plus(
                        ring_acc_head(
                            mem_acc(
                                source.type_word64,
                                ring_handle_used_ring_offset(
                                    arg(ring_handle()),
                                ),
                                arg(Mem)
                            ),
                            arg(Mem)
                        ),
                        u32(1)
                    ),
                    ring_acc_sz(
                        mem_acc(
                            source.type_word64,
                            ring_handle_used_ring_offset(
                                arg(ring_handle()),
                            ),
                            arg(Mem)
                        ),
                        arg(Mem)
                    ),
                ),
                ring_acc_tail(
                    mem_acc(
                        source.type_word64,
                        ring_handle_used_ring_offset(
                            arg(ring_handle()),
                        ),
                        arg(Mem)
                    ),
                    arg(Mem)
                ),
            ),
        ),
        postcondition=conjs(
            eq(
                cli_addr_ghost,
                u64(0)
            ),
            eq(
                arg(mux_size_ghost),
                mux_size_ghost
            ),
            eq(
                arg(mux_addr_ghost),
                mux_addr_ghost
            ),
            eq(
                arg(copied_ghost),
                copied_ghost
            ),
            fits_pointer(
                arg(ring_handle())
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            fits_pointer(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                arg(ring_handle()),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),

            distinct(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16,

                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    Mem
                ),
                2**16
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_free_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                Mem
            ),
            ring_wf(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                ),
                Mem
            ),
            enqueue_post(
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        arg(ring_handle())
                    ),
                    arg(Mem)
                )
            )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.cancel_signal": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(
            eq(Mem,
                mem_upd(
                    source.type_word8,
                    ring_consumer_signalled_offset(arg(ring('ring_buffer'))),
                    char(1),
                    arg(Mem)
                )
               )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.require_signal": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(
            eq(Mem, arg(Mem)),
            eq(u8ret,
               bv8eq(
                   mem_acc(
                       source.type_word8,
                       ring_consumer_signalled_offset(
                           arg(ring('ring_buffer'))
                       ),
                       arg(Mem)
                   ),
                   char(0)
               )
               )
        ),
        loop_iterations={},
        loop_invariants={}
    ),
    "tmp.sel4cp_notify": source.Ghost(
        precondition=conjs(),
        postcondition=eq(Mem, arg(Mem)),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.sel4cp_notify_delayed": source.Ghost(
        precondition=conjs(),
        postcondition=eq(Mem, arg(Mem)),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.request_signal": source.Ghost(
        precondition=conjs(
        ),
        postcondition=conjs(
            eq(Mem,
                mem_upd(
                    source.type_word8,
                    ring_consumer_signalled_offset(arg(ring('ring_buffer'))),
                    char(0),
                    arg(Mem)
                )
               )
        ),
        loop_invariants={},
        loop_iterations={}
    ),
    "tmp.rx_return_outer": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={
            lh('43'): conjs()
        },
        loop_iterations={
            lh('43'): source.empty_loop_ghost
        }
    ),
    "tmp.rx_return": source.Ghost(
        precondition=conjs(),
        postcondition=conjs(),
        loop_invariants={
            lh('23'): conjs(
                g(ucharv('reprocess')),
                mem_assigned(),
                htd_assigned(),
                pms_assigned(),
                ghost_asserts_assigned()
            ),
            lh('63'): conjs(
                g(ucharv('reprocess')),
                mem_assigned(),
                htd_assigned(),
                pms_assigned(),
                ghost_asserts_assigned()
            )
        },
        loop_iterations={
            lh('23'): source.LoopIterationGhost(
                pre_iter=conjs(
                ),
                post_iter=conjs(
                )
            ),
            lh('63'): source.LoopIterationGhost(
                pre_iter=conjs(
                ),
                post_iter=conjs(
                )
            )
        }
    )
}
