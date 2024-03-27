import smt
import dataclasses
from ghost_data_helpers import *
from typing import Mapping, NamedTuple, Tuple
from typing_extensions import assert_never
from copy_spec import *
import dsa
import source
import nip
import assume_prove as ap


class EvalPoint(NamedTuple):
    at: source.NodeName
    eval_filter: source.ExprVarT[source.ProgVarName]
    e: source.ExprT[source.ProgVarName]


evals: Mapping[str, Mapping[str, list[EvalPoint]]] = {
    "examples/out_copy.txt": {
        "tmp.enqueue": [
            EvalPoint(
                source.NodeName("post_condition"),
                Mem,
                mem_acc(
                    source.type_word32,
                    ring_buffers_offset(ring()),
                    Mem
                ),
            )
        ],
        "tmp.dequeue_used": [
            EvalPoint(
                source.NodeName("post_condition"),
                Mem,
                mem_acc(
                    source.type_word64,
                    ring_handle_used_ring_offset(
                        ring_handle(),
                    ),
                    Mem
                )
            )
        ]
    }
}


def replace_with_incs(context: Mapping[source.ProgVarName | nip.GuardVarName, dsa.IncarnationNum], e: source.ExprT[source.ProgVarName]) -> source.ExprT[dsa.Incarnation[source.ProgVarName | nip.GuardVarName]]:
    if isinstance(e, source.ExprNum):
        return e
    elif isinstance(e, source.ExprVar):
        return source.ExprVar(e.typ, name=dsa.Incarnation(e.name, context[e.name]))
    elif isinstance(e, source.ExprOp):
        return source.ExprOp(e.typ, source.Operator(e.operator), operands=tuple(
            replace_with_incs(context, operand) for operand in e.operands
        ))
    elif isinstance(e, source.ExprType | source.ExprSymbol):
        return e
    elif isinstance(e, source.ExprFunction):
        return source.ExprFunction(e.typ, e.function_name, [replace_with_incs(context, arg) for arg in e.arguments], )
    else:
        assert_never(e)


def find_vars_for_eval(filename: str, fn_name: str, fn: dsa.Function) -> list[Tuple[str, source.ExprT[ap.VarName]]]:
    if filename not in evals or fn_name not in evals[filename]:
        return []
    points = evals[filename][fn_name]
    exprs: list[Tuple[str, source.ExprT[ap.VarName]]] = []
    for point in points:
        assert point.at in fn.nodes, f"eval point written for {point.at} but {point.at} isn't in the nodes"
        found_max_var = None
        incs: dict[source.ProgVarName |
                   nip.GuardVarName, dsa.IncarnationNum] = {}
        for var in source.used_variables_in_node(fn.nodes[point.at]):
            incs[var.name.base] = var.name.inc
            if var.name.base == point.eval_filter.name:
                if found_max_var is None:
                    found_max_var = var
                assert found_max_var is not None
                if found_max_var.name.inc > var.name.inc:
                    found_max_var = var

        assert found_max_var is not None

        for i in range(1, found_max_var.name.inc + 1):
            new_dsa_var = dsa.Incarnation(
                found_max_var.name.base, dsa.IncarnationNum(i))
            incs[point.eval_filter.name] = new_dsa_var.inc
            expr = ap.convert_expr_dsa_vars_to_ap(
                replace_with_incs(incs, point.e))
            exprs.append((f"eval_{point.eval_filter.name}_{i}", expr))
    return exprs


def make_smt_commands(es: list[Tuple[str, source.ExprT[ap.VarName]]]) -> list[smt.Cmd]:
    cmds: list[smt.Cmd] = []
    for (name, e) in es:
        ident = smt.identifier(ap.VarName(name))
        cmds.append(smt.CmdDeclareFun(ident, (), e.typ))
        cmds.append(
            smt.CmdAssert(
                eq(
                    source.ExprVar(e.typ, ap.VarName(name)),
                    e
                )
            )
        )
    return cmds
