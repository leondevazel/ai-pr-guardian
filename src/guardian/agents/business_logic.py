from guardian.agents.base import ReviewAgent


class BusinessLogicAgent(ReviewAgent):
    name = "business_logic"
    mandate = (
        "off-by-one and boundary errors, inverted or incomplete conditionals, unhandled None/empty "
        "cases, and silent behavior changes that existing tests would not catch. Compare the changed "
        "code against what the surrounding function and its tests imply it should do."
    )
    must_not = "flag anything you cannot tie to a specific line, or speculate about intent"

    def _extra_context(self, contexts) -> list[str]:
        blocks = []
        for ctx in contexts:
            if ctx.enclosing_function:
                blocks.append(f"## Enclosing function\n```\n{ctx.enclosing_function}\n```")
            if ctx.related_tests:
                blocks.append(
                    "## Existing tests touching this code\n"
                    + "\n".join(f"- {path}" for path in ctx.related_tests)
                )
        return blocks
