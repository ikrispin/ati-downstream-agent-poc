"""Run with the MAS environment against tests/probe_agent.py on port 8122."""

from types import SimpleNamespace

from dotenv import dotenv_values
from mas.elements.llms.common.chat.message import ChatMessage, Role
from mas.elements.nodes.a2a_agent.a2a_agent_node import A2AAgentNode
from mas.elements.providers.a2a_client import A2AProvider
from pydantic import HttpUrl

token = dotenv_values(".env")["ATI_A2A_TOKEN"]
provider = A2AProvider(
    base_url=HttpUrl("http://127.0.0.1:8122"), headers={"Authorization": f"Bearer {token}"}
)
for cve, expected in [("CVE-2023-38545", True), ("CVE-2020-1111", False)]:
    for streaming in (False, True):
        node = SimpleNamespace(
            uid="probe",
            display_name="probe",
            is_streaming=lambda: streaming,
            a2a_provider=provider,
            _stream=lambda event: None,
            _wait_for_completion=True,
            _poll_interval=0.1,
            _max_poll_attempts=20,
        )
        method = (
            A2AAgentNode._delegate_with_streaming
            if streaming
            else A2AAgentNode._delegate_without_streaming
        )
        message, metadata = method(
            node,
            ChatMessage(role=Role.USER, content=cve),
            SimpleNamespace(thread_id="probe-context"),
        )
        result = A2AAgentNode._create_agent_result(node, message, metadata)
        assert result.success is expected, (cve, streaming, metadata, result.success)
        print(f"{cve} streaming={streaming} success={result.success}: PASS")

# A stream closing without a terminal event must never become success.
node.a2a_provider = SimpleNamespace(
    stream_message_sync=lambda **kwargs: iter(
        [ChatMessage(role=Role.ASSISTANT, content="An incomplete response")]
    )
)
message, metadata = A2AAgentNode._delegate_with_streaming(
    node,
    ChatMessage(role=Role.USER, content="CVE-2023-38545"),
    SimpleNamespace(thread_id="probe-context"),
)
assert not A2AAgentNode._create_agent_result(node, message, metadata).success
print("Incomplete stream success=False: PASS")
