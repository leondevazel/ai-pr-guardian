import os
from pathlib import Path

import anthropic

HAIKU = "claude-haiku-4-5-20251001"
SONNET = "claude-sonnet-5"

# Per-million-token prices, used only to report run cost (agent.md §6).
PRICES = {
    HAIKU: {"in": 1.00, "out": 5.00},
    SONNET: {"in": 3.00, "out": 15.00},
}


def load_api_key() -> str:
    """Environment wins; otherwise read .env from the repo root. Never logged, never printed."""
    if key := os.environ.get("ANTHROPIC_API_KEY"):
        return _clean(key)

    env_file = Path(__file__).resolve().parents[3] / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "ANTHROPIC_API_KEY":
                return _clean(value)

    raise RuntimeError(
        "No ANTHROPIC_API_KEY found. Create a .env file in the project root containing:\n"
        "ANTHROPIC_API_KEY=sk-ant-...\n"
        "(.env is gitignored.)"
    )


def _clean(value: str) -> str:
    """Absorb what pasting into a hosting dashboard tends to add: whitespace, quotes, or the
    whole `NAME=value` line instead of just the value."""
    value = value.strip()
    if value.upper().startswith("ANTHROPIC_API_KEY"):
        value = value.split("=", 1)[-1].strip()
    return value.strip("\"'").strip()


class AnthropicClient:
    """The only place that talks to the API. Agents take a client so tests can pass a fake."""

    def __init__(self, api_key: str | None = None, max_tokens: int = 2000):
        self._client = anthropic.Anthropic(api_key=api_key or load_api_key())
        self.max_tokens = max_tokens
        self.usage: list[dict] = []

    def complete(self, system: str, user: str, model: str) -> str:
        # No temperature knob: the Messages API in SDK 1.x dropped it. Run-to-run variance is
        # therefore a property of the benchmark, not something to suppress — evaluate.py measures
        # it by repeating runs instead of pretending the pipeline is deterministic.
        response = self._client.messages.create(
            model=model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        self.usage.append(
            {
                "model": model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        )
        return "".join(block.text for block in response.content if block.type == "text")

    def total_cost_usd(self) -> float:
        return sum(
            call["input_tokens"] / 1_000_000 * PRICES[call["model"]]["in"]
            + call["output_tokens"] / 1_000_000 * PRICES[call["model"]]["out"]
            for call in self.usage
            if call["model"] in PRICES
        )
