"""Run ATI evidence tools or call the native LSCore agent; never execute a custom loop."""

import argparse
import asyncio
import json
from pathlib import Path

from .client import assess_batch, save_private_report
from .config import Settings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("tools", help="Serve the read-only ATI domain MCP tools on loopback")
    commands.add_parser("support-login", help="Authorize the existing Support MCP connection")
    configure = commands.add_parser("configure", help="Write the native LSCore development config")
    configure.add_argument("--output", type=Path, default=Path(".local/lscore.yaml"))
    assess = commands.add_parser("assess", help="Submit explicit CVEs to the native LSCore loop")
    assess.add_argument("--cve", action="append", required=True)
    assess.add_argument("--environment", required=True)
    assess.add_argument("--concurrency", type=int, default=2)
    assess.add_argument("--output", type=Path, required=True)
    show = commands.add_parser("show-assessment", help="Export a private domain evidence record")
    show.add_argument("--assessment-id", required=True)
    show.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        settings = Settings.load()
        if args.command == "tools":
            from .mcp_server import build_server

            build_server(settings.domain(), port=settings.mcp_port).run(transport="streamable-http")
        elif args.command == "support-login":
            from .oauth import login

            asyncio.run(login(settings.support_url, settings.state_dir / "oauth"))
        elif args.command == "configure":
            from .native_config import write_native_config

            write_native_config(settings, args.output)
            print(json.dumps({"configuration_written": True, "execution_owner": "lscore_native"}))
        elif args.command == "show-assessment":
            save_private_report(args.output, settings.domain().store.read(args.assessment_id))
            print(json.dumps({"private_record_written": True}))
        else:
            report = asyncio.run(
                assess_batch(settings, args.cve, args.environment, concurrency=args.concurrency)
            )
            save_private_report(args.output, report)
            print(
                json.dumps(
                    {
                        "execution_owner": "lscore_native",
                        "data_mode": report["data_mode"],
                        "assessments": len(report["results"]),
                        "outcomes": [item["domain_outcome"] for item in report["results"]],
                        "native_failures": sum(
                            item["native_status"] != "request_completed"
                            for item in report["results"]
                        ),
                    },
                    indent=2,
                )
            )
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
