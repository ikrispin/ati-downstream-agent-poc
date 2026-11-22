# Reproduction baseline

This is the baseline used for the November 2026 downstream integration lab.
It records selected versions rather than claiming they are the latest releases.

| Component | Selected baseline |
|---|---|
| ATI A2A SDK | `a2a-sdk==1.3.1` |
| ATI MCP SDK | `mcp==1.30.0` |
| Python | `3.12.16` |
| Node, optional MAS UI | `22.23.5` |
| MAS Git revision | `d5a93001da2836177252d5719f7de57f698edcee` |
| MAS UI Git revision | `986a54ad6ec1cfc47cfc7028253f5ac8bb6b7c64` |

ATI's complete Python dependency resolution and package hashes are in `uv.lock`.
MongoDB, Redis, and Temporal images are pinned by digest in `compose.yaml`.
The optional runtime installer validates its pinned Node archive checksum and
installs runtimes under `.local/tools/` without replacing system installations.

MAS and its UI are obtained separately using the repository URLs supplied to
`scripts/bootstrap.sh`. They retain their own lockfiles. The MAS baseline uses
A2A SDK `1.2.2`; its communication with the independently pinned ATI SDK was
tested. The bootstrap retains the platform's frozen dependency installation.

Two local MAS patches are included for A2A outcome conversion/streaming metadata
and omission of empty model tool lists. Reassess them against any new platform
revision rather than assuming they remain necessary or applicable.

MCP 1.30.0 was retained after a live MCP 2.x trial encountered incompatible OAuth
metadata. The OAuth renewal adapter uses private interfaces of the pinned 1.x
SDK and needs review when changing that version. No issuer validation was relaxed.

See [verification notes](VERIFICATION.md) for automated and historical live checks.
