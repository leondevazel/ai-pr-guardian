from guardian.agents.base import ReviewAgent


class ArchitectureAgent(ReviewAgent):
    name = "architecture"
    mandate = (
        "breaking interface changes, layering violations (e.g. a data layer reaching into HTTP "
        "concerns), duplicated responsibility, and error handling that swallows failures or loses "
        "data. Judge the shape of the change against the module it lives in."
    )
    must_not = "re-flag security vulnerabilities or pure style nits"

    def _extra_context(self, contexts) -> list[str]:
        imports = sorted({imp for ctx in contexts for imp in ctx.imports})
        if not imports:
            return []
        return [f"## Imports of the changed files\n{', '.join(imports)}"]
