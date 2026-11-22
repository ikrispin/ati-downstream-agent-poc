"""Check optional tools in the pinned MAS model adapter without calling a model."""

from contextlib import nullcontext
from types import SimpleNamespace

from mas.elements.llms.common.chat.message import ChatMessage, Role
from mas.elements.llms.openai_compatible.openai_compatible import OpenAICompatibleLLM
from openai.types.chat import ChatCompletion, ChatCompletionChunk


def main():
    tracing = SimpleNamespace(
        trace_llm=lambda **kwargs: nullcontext(SimpleNamespace(update=lambda **values: None))
    )
    for streaming in (False, True):
        for tools in (None, [{"type": "function", "function": {"name": "demo"}}]):

            def create(**kwargs):
                if tools:
                    assert kwargs.get("tools") == tools
                else:
                    assert "tools" not in kwargs, "Synthesis must omit an empty tools parameter"
                if streaming:
                    return iter(
                        [
                            ChatCompletionChunk(
                                id="test",
                                created=0,
                                model="test",
                                object="chat.completion.chunk",
                                choices=[
                                    {
                                        "index": 0,
                                        "delta": {"content": "84"},
                                        "finish_reason": "stop",
                                    }
                                ],
                            )
                        ]
                    )
                return ChatCompletion(
                    id="test",
                    created=0,
                    model="test",
                    object="chat.completion",
                    choices=[
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "84"},
                            "finish_reason": "stop",
                        }
                    ],
                )

            model = OpenAICompatibleLLM(
                base_url="http://unused", model_name="test", api_key="test", tracing=tracing
            )
            model._tools = tools
            model._client = SimpleNamespace(
                chat=SimpleNamespace(completions=SimpleNamespace(create=create))
            )
            messages = [ChatMessage(role=Role.USER, content="A test request")]
            result = list(model.stream(messages)) if streaming else model.chat(messages)
            assert result == ["84"] if streaming else result.content == "84"
            print(f"streaming={streaming} tools={bool(tools)}: PASS")


if __name__ == "__main__":
    main()
