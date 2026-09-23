import os

import anthropic

HAIKU = "claude-haiku-4-5-20251001"
SONNET = "claude-sonnet-5"

# Per-million-token prices, used only to report run cost (agent.md §6).
PRICES = {
    HAIKU: {"in": 1.00, "out": 5.00},
    SONNET: {"in": 3.00, "out": 15.00},
}


class AnthropicClient:
    """The only place that talks to the API. Agents take a client so tests can pass a fake."""

    def __init__(self, api_key: str | None = None, max_tokens: int = 2000):
        self._client = anthropic.Anthropic(api_key=api_key or os.environ["ANTHROPIC_API_KEY"])
        self.max_tokens = max_tokens
        self.usage: list[dict] = []

    def complete(self, system: str, user: str, model: str) -> str:
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
