import ast
from dataclasses import dataclass, field
from pathlib import Path

WINDOW = 20


@dataclass
class FileContext:
    enclosing_function: str = ""
    related_tests: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


def get_context(repo_path: str, file: str, line: int) -> FileContext:
    target = Path(repo_path) / file
    if not target.is_file():
        return FileContext()

    source = target.read_text(encoding="utf-8", errors="replace")
    lines = source.splitlines()

    if target.suffix != ".py":
        return FileContext(enclosing_function=_window(lines, line))

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return FileContext(enclosing_function=_window(lines, line))

    node = _enclosing_function(tree, line)
    if node is None:
        return FileContext(
            enclosing_function=_window(lines, line),
            imports=_imports(tree),
        )

    return FileContext(
        enclosing_function="\n".join(lines[node.lineno - 1 : node.end_lineno]),
        related_tests=_tests_referencing(repo_path, node.name),
        imports=_imports(tree),
    )


def _window(lines: list[str], line: int) -> str:
    start = max(0, line - 1 - WINDOW // 2)
    return "\n".join(lines[start : line - 1 + WINDOW // 2])


def _enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | None:
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    # Innermost wins: a nested def is more specific than the function wrapping it.
    return max(candidates, key=lambda n: n.lineno, default=None)


def _imports(tree: ast.Module) -> list[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _tests_referencing(repo_path: str, symbol: str) -> list[str]:
    matches = []
    for path in Path(repo_path).rglob("test_*.py"):
        content = path.read_text(encoding="utf-8", errors="replace")
        if symbol in content:
            matches.append(path.relative_to(repo_path).as_posix())
    return matches
