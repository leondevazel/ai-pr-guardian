from guardian.agents.base import ReviewAgent


class SecurityAgent(ReviewAgent):
    name = "security"
    mandate = (
        "injection (SQL, command, template), auth/authz bypass, hardcoded secrets, unsafe "
        "deserialization, SSRF, path traversal, and unsafe crypto. Judge whether user-controlled "
        "data can reach a dangerous sink in the code as changed."
    )
    must_not = "comment on style, naming, formatting, or performance"
