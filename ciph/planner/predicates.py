"""
ciph.planner.predicates - Safe AST Predicate Validator (Zero eval).
Evaluates plan step success conditions deterministically against receipt results.
"""

import ast
import operator
from typing import Dict, Any


SAFE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}

SAFE_UNARY_OPERATORS = {
    ast.Not: operator.not_,
    ast.USub: operator.neg,
}


class SafePredicateEvaluator(ast.NodeVisitor):
    """Safely evaluates boolean AST expressions against context data without eval()."""

    def __init__(self, context: Dict[str, Any]):
        self.context = context

    def evaluate(self, node: ast.AST) -> Any:
        return self.visit(node)

    def visit_Expression(self, node: ast.Expression) -> Any:
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant) -> Any:
        return node.value

    def visit_Name(self, node: ast.Name) -> Any:
        return self.context.get(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        val = self.visit(node.value)
        if isinstance(val, dict):
            return val.get(node.attr)
        return getattr(val, node.attr, None)

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        val = self.visit(node.value)
        slice_val = self.visit(node.slice)
        if isinstance(val, (dict, list, tuple, str)):
            try:
                return val[slice_val]
            except Exception:
                return None
        return None

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        op_type = type(node.op)
        if op_type in SAFE_UNARY_OPERATORS:
            return SAFE_UNARY_OPERATORS[op_type](self.visit(node.operand))
        raise ValueError(f"Unsupported unary operator: {op_type}")

    def visit_BoolOp(self, node: ast.BoolOp) -> bool:
        if isinstance(node.op, ast.And):
            return all(self.visit(v) for v in node.values)
        elif isinstance(node.op, ast.Or):
            return any(self.visit(v) for v in node.values)
        raise ValueError(f"Unsupported boolean operator: {type(node.op)}")

    def visit_Compare(self, node: ast.Compare) -> bool:
        left = self.visit(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            op_type = type(op)
            if op_type not in SAFE_OPERATORS:
                raise ValueError(f"Unsupported comparison operator: {op_type}")
            right = self.visit(comparator)
            if not SAFE_OPERATORS[op_type](left, right):
                return False
            left = right
        return True

    def generic_visit(self, node: ast.AST):
        raise ValueError(f"Unsupported AST node in predicate: {type(node).__name__}")


def evaluate_success_condition(condition_str: str, context: Dict[str, Any]) -> bool:
    """
    Safely evaluate a condition string like 'exit_code == 0 and results.status == 200'
    against the execution context without Python eval().
    """
    if not condition_str or condition_str.strip() in ("", "true", "True"):
        return True
    if condition_str.strip() in ("false", "False"):
        return False
    try:
        parsed = ast.parse(condition_str.strip(), mode='eval')
        evaluator = SafePredicateEvaluator(context)
        return bool(evaluator.evaluate(parsed))
    except Exception:
        return False
