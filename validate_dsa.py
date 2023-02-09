from typing import Collection, Sequence
from typing_extensions import assert_never
import abc_cfg
import source
import nip
import dsa


def compute_all_path(cfg: abc_cfg.CFG) -> Sequence[Sequence[source.NodeName]]:
    # binary number, 1 means go left 0 means go right
    # start exploring tree all the way from the left
    all_paths: list[list[source.NodeName]] = []

    def dfs(n: source.NodeName) -> None:
        all_paths[-1].append(n)

        succs = cfg.all_succs[n]
        if len(succs) == 0:
            return

        if len(succs) == 1 and (n, succs[0]) not in cfg.back_edges:
            dfs(succs[0])
            return

        path_so_far = list(all_paths[-1])
        for i, succ in enumerate(succs):
            if (n, succ) not in cfg.back_edges:
                if i > 0:
                    all_paths.append(path_so_far)
                dfs(succ)

    for n, preds in cfg.all_preds.items():
        if len(preds) == 0:
            all_paths.append([])
            dfs(n)
    return all_paths


def ensure_assigned_at_most_once(func: dsa.Function, path: Collection[source.NodeName]) -> None:
    assigned_variables: list[dsa.Var[source.ProgVarName |
                                     nip.GuardVarName]] = []
    for node in path:
        assigned_variables.extend(
            source.assigned_variables_in_node(func, node, with_loop_targets=True))
    assert len(assigned_variables) == len(set(assigned_variables))


def ensure_using_latest_incarnation(func: dsa.Function, path: Collection[source.NodeName]) -> None:
    latest_assignment: dict[source.ExprVarT[source.ProgVarName |
                                            nip.GuardVarName], dsa.IncarnationNum] = {}
    for arg in func.arguments:
        prog_var, inc = dsa.unpack_dsa_var(arg)
        assert prog_var not in latest_assignment
        latest_assignment[prog_var] = inc

    for n in path:
        if n in (source.NodeNameErr, source.NodeNameRet):
            continue

        for dsa_var in source.used_variables_in_node(func.nodes[n]):
            # loop targets are havoc'd at the top of the loop header
            # that is, it is legal to use them in the loop header itself
            if loop_header := func.is_loop_header(n):
                for target in func.loops[loop_header].targets:
                    prog_var, inc = dsa.unpack_dsa_var(target)
                    latest_assignment[prog_var] = inc

            prog_var, inc = dsa.unpack_dsa_var(dsa_var)
            if prog_var in latest_assignment:
                assert inc == latest_assignment[prog_var], f"{prog_var=} {n=} {path=}"
            # we don't assert that inc == 1 otherwise, because prog_var:1
            # might be used on some other path that joins with our own(and so
            # inc would be 2 for example)

        for dsa_var in source.assigned_variables_in_node(func, n, with_loop_targets=True):
            prog_var, inc = dsa.unpack_dsa_var(dsa_var)
            latest_assignment[prog_var] = inc


def ensure_valid_dsa(dsa_func: dsa.Function) -> None:
    all_paths = compute_all_path(dsa_func.cfg)
    for i, path in enumerate(all_paths):
        ensure_assigned_at_most_once(dsa_func, path)
        ensure_using_latest_incarnation(dsa_func, path)


def assert_expr_equals_mod_dsa(lhs: source.ExprT[source.ProgVarName | nip.GuardVarName], rhs: source.ExprT[dsa.Incarnation[source.ProgVarName | nip.GuardVarName]]) -> None:
    assert lhs.typ == rhs.typ

    if isinstance(lhs, source.ExprNum | source.ExprSymbol | source.ExprType):
        assert lhs == rhs
    elif isinstance(lhs, source.ExprVar):
        assert isinstance(rhs, source.ExprVar)
        assert lhs.name == dsa.unpack_dsa_var_name(rhs.name)[0]
    elif isinstance(lhs, source.ExprOp):
        assert isinstance(rhs, source.ExprOp)
        assert lhs.operator == rhs.operator
        assert len(lhs.operands) == len(rhs.operands)
        for i in range(len(lhs.operands)):
            assert_expr_equals_mod_dsa(lhs.operands[i], rhs.operands[i])
    elif isinstance(lhs, source.ExprFunction):
        assert isinstance(rhs, source.ExprFunction)
        assert lhs.function_name == rhs.function_name
        assert len(lhs.arguments) == len(rhs.arguments)
        for i in range(len(lhs.arguments)):
            assert_expr_equals_mod_dsa(lhs.arguments[i], rhs.arguments[i])
    else:
        assert_never(lhs)


def assert_var_equals_mod_dsa(prog: source.ExprVarT[source.ProgVarName | nip.GuardVarName], var: dsa.Var[source.ProgVarName | nip.GuardVarName]) -> None:
    assert prog == dsa.unpack_dsa_var(var)[0]


def assert_node_equals_mod_dsa(prog: source.Node[source.ProgVarName | nip.GuardVarName], node: source.Node[dsa.Incarnation[source.ProgVarName | nip.GuardVarName]]) -> None:
    if isinstance(prog, source.NodeBasic):
        assert isinstance(node, source.NodeBasic)

        assert len(prog.upds) == len(node.upds)
        for i in range(len(prog.upds)):
            assert_var_equals_mod_dsa(
                prog.upds[i].var, node.upds[i].var)

            assert_expr_equals_mod_dsa(
                prog.upds[i].expr, node.upds[i].expr)

    elif isinstance(prog, source.NodeCall):
        assert isinstance(node, source.NodeCall)

        assert len(prog.args) == len(node.args)
        for i in range(len(prog.args)):
            assert_expr_equals_mod_dsa(prog.args[i], node.args[i])

        assert len(prog.rets) == len(node.rets)
        for i in range(len(prog.rets)):
            assert_var_equals_mod_dsa(prog.rets[i], node.rets[i])

    elif isinstance(prog, source.NodeCond | source.NodeAssume):
        assert isinstance(node, source.NodeCond)
        assert_expr_equals_mod_dsa(prog.expr, node.expr)

    elif isinstance(prog, source.NodeEmpty):
        assert isinstance(node, source.NodeEmpty)
    else:
        assert_never(prog)


def assert_is_join_node(node: source.Node[dsa.Incarnation[source.ProgVarName | nip.GuardVarName]]) -> None:
    assert isinstance(node, dsa.NodeJoiner)
    for upd in node.upds:
        # ensure every update is of the form A.X = A.Y
        lhs_name, _ = dsa.unpack_dsa_var_name(upd.var.name)
        assert isinstance(upd.expr, source.ExprVar)
        rhs_name, _ = dsa.unpack_dsa_var_name(upd.expr.name)
        assert upd.var.typ == upd.expr.typ
        assert lhs_name == rhs_name


def ensure_correspondence(prog_func: source.Function[source.ProgVarName | nip.GuardVarName], dsa_func: dsa.Function) -> None:
    assert set(prog_func.nodes.keys()).issubset(dsa_func.nodes.keys())

    join_node_names: list[source.NodeName] = []

    for node_name in dsa_func.nodes:
        if node_name in (source.NodeNameErr, source.NodeNameRet):
            continue

        dsa_node = dsa_func.nodes[node_name]

        if node_name not in prog_func.nodes:
            assert_is_join_node(dsa_node)
            assert node_name.startswith('j')  # not required semantically
            join_node_names.append(node_name)
        else:
            prog_node = prog_func.nodes[node_name]
            assert_node_equals_mod_dsa(prog_node, dsa_node)

    for node_name in prog_func.traverse_topologically():
        prog_succs = prog_func.cfg.all_succs[node_name]
        dsa_succs = dsa_func.cfg.all_succs[node_name]

        if prog_succs == dsa_succs:
            continue

        # the only reason the successors wouldn't been the same is if a dsa.dsa
        # successor was a join node.

        assert len(prog_succs) == len(dsa_succs)
        for i in range(len(prog_succs)):
            if prog_succs[i] == dsa_succs[i]:
                continue

            # we must have
            # prog:  a -----------> b
            # dsa.dsa :  a --> join --> b

            assert dsa_succs[i] in join_node_names
            join_node_succs = dsa_func.cfg.all_succs[dsa_succs[i]]
            assert len(join_node_succs) == 1
            assert join_node_succs[0] == prog_succs[i]


def ensure_valid_contexts(func: dsa.Function) -> None:
    new_contexts: dict[source.NodeName, dict[source.ExprVarT[source.ProgVarName |
                                                             nip.GuardVarName], dsa.IncarnationNum]] = {}
    new_contexts[func.cfg.entry] = {dsa.get_base_var(
        var): dsa.IncarnationBase for var in func.arguments}
    assert new_contexts[func.cfg.entry] == func.contexts[func.cfg.entry]

    for n in func.traverse_topologically(skip_err_and_ret=True):
        if n == func.cfg.entry:
            continue
        assert n not in new_contexts, f'{n=}'

        conflicting_vars: set[source.ExprVarT[source.ProgVarName |
                                              nip.GuardVarName]] = set()
        new_contexts[n] = {}
        for p in func.acyclic_preds_of(n):
            assert p in new_contexts, f'{n=} {p=}'
            for var, inc in new_contexts[p].items():

                if var in new_contexts[n] and new_contexts[n][var] != inc:
                    conflicting_vars.add(var)

                new_contexts[n][var] = inc

        assert len(conflicting_vars) == 0

        for v in source.assigned_variables_in_node(func, n, with_loop_targets=True):
            new_contexts[n][dsa.get_base_var(v)] = v.name.inc

        assert new_contexts[n] == func.contexts[n], f'{n=} {new_contexts[n]=}\n{func.contexts[n]}'

    assert new_contexts == func.contexts


def validate(func: source.Function[source.ProgVarName | nip.GuardVarName], dsa_func: dsa.Function) -> None:
    ensure_correspondence(func, dsa_func)
    ensure_valid_dsa(dsa_func)
    ensure_valid_contexts(dsa_func)
