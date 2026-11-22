"""Configurable GLM/OpenAI-compatible model adapter."""

import httpx


class ChatModel:
    def __init__(self, base_url: str, model: str, api_key: str, *, timeout: float = 90):
        self.base_url, self.model, self.api_key = base_url.rstrip("/"), model, api_key
        self.timeout = timeout

    async def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "auto",
                    "temperature": 0,
                    "max_tokens": 4096,
                },
            )
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]
            return {
                key: message[key] for key in ("role", "content", "tool_calls") if key in message
            }
