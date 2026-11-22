"""Official A2A SDK transport around the independent investigation core."""

import asyncio
import hmac
from uuid import uuid4

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
from google.protobuf.json_format import ParseDict
from google.protobuf.struct_pb2 import Value
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .models import InvestigationRequest


class ATIExecutor(AgentExecutor):
    def __init__(self, investigator):
        self.investigator = investigator
        self.running = {}

    async def execute(self, context, event_queue):
        task_id, context_id = context.task_id, context.context_id
        updater = TaskUpdater(event_queue, task_id, context_id)
        self.running[task_id] = asyncio.current_task()
        try:
            if not context.current_task:
                await event_queue.enqueue_event(
                    Task(
                        id=task_id,
                        context_id=context_id,
                        status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    )
                )
            await updater.update_status(TaskState.TASK_STATE_WORKING)
            request = InvestigationRequest.parse(context.get_user_input(), context_id)
            result = await self.investigator.investigate(request)
            await updater.add_artifact([Part(text=result.answer)], name="ATI answer")
            await updater.add_artifact(
                [Part(data=ParseDict(result.to_dict(), Value()))], name="ATI investigation record"
            )
            state = (
                TaskState.TASK_STATE_FAILED
                if result.status == "failed"
                else TaskState.TASK_STATE_COMPLETED
            )
            await updater.update_status(
                state, metadata={"investigation_id": result.run_id, "ati_outcome": result.status}
            )
        except asyncio.CancelledError:
            await updater.update_status(TaskState.TASK_STATE_CANCELED)
        except Exception as exc:
            # Input/claim errors are safe; do not return transport/model exception bodies.
            text = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
            await updater.update_status(
                TaskState.TASK_STATE_FAILED,
                Message(message_id=uuid4().hex, role=Role.ROLE_AGENT, parts=[Part(text=text)]),
            )
        finally:
            self.running.pop(task_id, None)

    async def cancel(self, context, event_queue):
        running = self.running.get(context.task_id)
        if running:
            running.cancel()


def create_app(investigator, public_url: str, token: str):
    if not token:
        raise ValueError("ATI A2A service token is required")
    card = AgentCard(
        name="ATI independent downstream lab",
        description=(
            "Investigate one CVE using vendor, OSIDB, Lightspeed and a supplied Support Case."
        ),
        version="0.1.0",
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain", "application/json"],
        supported_interfaces=[
            AgentInterface(
                url=public_url.rstrip("/") + "/a2a/jsonrpc",
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=True),
        security_schemes={
            "bearer": SecurityScheme(
                http_auth_security_scheme=HTTPAuthSecurityScheme(scheme="bearer")
            )
        },
        security_requirements=[SecurityRequirement(schemes={"bearer": {"list": []}})],
        skills=[
            AgentSkill(
                id="investigate_cve",
                name="Four-source ATI investigation",
                description="Supply one CVE and optionally an explicit Support Case.",
                tags=["security", "CVE", "ATI"],
            )
        ],
    )
    handler = DefaultRequestHandler(ATIExecutor(investigator), InMemoryTaskStore(), card)

    async def health(_):
        return JSONResponse({"service": "ati-downstream", "status": "ready"})

    app = Starlette(
        routes=[
            Route("/health", health),
            *create_agent_card_routes(card),
            *create_jsonrpc_routes(handler, "/a2a/jsonrpc", enable_v0_3_compat=True),
        ]
    )

    async def authenticated(scope, receive, send):
        if scope["type"] == "http" and scope["path"] not in {
            "/health",
            "/.well-known/agent-card.json",
        }:
            headers = dict(scope["headers"])
            actual = headers.get(b"authorization", b"").decode()
            if not hmac.compare_digest(actual, f"Bearer {token}"):
                return await JSONResponse({"error": "ATI bearer token required"}, status_code=401)(
                    scope, receive, send
                )
        return await app(scope, receive, send)

    return authenticated
