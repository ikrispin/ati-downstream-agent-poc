"""Arithmetic-only A2A counterpart for the MAS agent-selection experiment."""

import argparse
import hmac
import re
from decimal import Decimal, DecimalException
from uuid import uuid4

import uvicorn
from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    HTTPAuthSecurityScheme,
    Message,
    Part,
    Role,
    SecurityRequirement,
    SecurityScheme,
    Task,
    TaskState,
    TaskStatus,
)
from starlette.applications import Starlette
from starlette.responses import JSONResponse

from .config import Settings


def calculate(question: str) -> str:
    number = r"(-?\d{1,12}(?:\.\d{1,8})?)"
    match = re.search(
        rf"(?:calculate|compute|what is)\s+{number}\s*([+*/-])\s*{number}(?![\d.*/])",
        question,
        re.IGNORECASE,
    )
    if not match:
        raise ValueError("Use Calculate <number> <+|-|*|/> <number>; arithmetic only")
    left, operation, right = match.groups()
    a, b = Decimal(left), Decimal(right)
    try:
        if operation == "+":
            answer = a + b
        elif operation == "-":
            answer = a - b
        elif operation == "*":
            answer = a * b
        else:
            answer = a / b
    except DecimalException as exc:
        raise ValueError("Arithmetic operation is undefined") from exc
    return format(answer.normalize(), "f")


class ArithmeticExecutor(AgentExecutor):
    async def execute(self, context, event_queue):
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        if not context.current_task:
            await event_queue.enqueue_event(
                Task(
                    id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                )
            )
        try:
            answer = calculate(context.get_user_input().rsplit("CURRENT TASK:", 1)[-1])
            await updater.add_artifact([Part(text=answer)], name="Arithmetic result")
            await updater.update_status(TaskState.TASK_STATE_COMPLETED)
        except ValueError as exc:
            await updater.update_status(
                TaskState.TASK_STATE_FAILED,
                Message(message_id=uuid4().hex, role=Role.ROLE_AGENT, parts=[Part(text=str(exc))]),
            )

    async def cancel(self, context, event_queue):
        await TaskUpdater(event_queue, context.task_id, context.context_id).update_status(
            TaskState.TASK_STATE_CANCELED
        )


def create_app(public_url: str, token: str):
    if not token:
        raise ValueError("Reference agent token is required")
    card = AgentCard(
        name="Arithmetic reference agent",
        description=(
            "Performs simple arithmetic with two numbers and +, -, *, or /. "
            "Use for arithmetic requests only. Has no security, CVE, or source lookup capability."
        ),
        version="0.1.0",
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        supported_interfaces=[
            AgentInterface(
                url=public_url.rstrip("/") + "/a2a/jsonrpc",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=False),
        security_schemes={
            "bearer": SecurityScheme(
                http_auth_security_scheme=HTTPAuthSecurityScheme(scheme="bearer")
            )
        },
        security_requirements=[SecurityRequirement(schemes={"bearer": {"list": []}})],
        skills=[
            AgentSkill(
                id="calculate",
                name="Two-number arithmetic",
                description=(
                    "Send Calculate <number> <operator> <number>, for example Calculate 12 * 7."
                ),
                tags=["arithmetic"],
                examples=["Calculate 12 * 7", "Calculate 2.5 + 0.5"],
            )
        ],
    )
    handler = DefaultRequestHandler(ArithmeticExecutor(), InMemoryTaskStore(), card)
    app = Starlette(
        routes=[
            *create_agent_card_routes(card),
            *create_jsonrpc_routes(handler, "/a2a/jsonrpc", enable_v0_3_compat=True),
        ]
    )

    async def authenticated(scope, receive, send):
        if scope["type"] == "http" and scope["path"] != "/.well-known/agent-card.json":
            actual = dict(scope["headers"]).get(b"authorization", b"").decode()
            if not hmac.compare_digest(actual, f"Bearer {token}"):
                return await JSONResponse({"error": "Bearer token required"}, status_code=401)(
                    scope, receive, send
                )
        return await app(scope, receive, send)

    return authenticated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8123)
    args = parser.parse_args()
    uvicorn.run(
        create_app(f"http://127.0.0.1:{args.port}", Settings.load().token),
        host="127.0.0.1",
        port=args.port,
    )


if __name__ == "__main__":
    main()
