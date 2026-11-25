"""Compare documented typed inference config with unchanged OGX synthesis.

All settings and keys are synthetic. This does not initialize the application
singleton, start a service, connect to an endpoint, or modify upstream source.
"""

import copy
import json

from models.config import InferenceConfiguration
from ogx_configuration import synthesize_configuration
from providers.inference.openai.provider import OpenAIInferenceProvider


def main():
    """Emit the independent configuration forwarding/replacement comparison."""
    connection = {
        "api_key": "fixture-only-no-secret",
        "base_url": "http://127.0.0.1:18141/v1",
    }
    inference = {
        "default_provider": "fixture",
        "default_model": "fixture-model",
        "providers": [{
            "id": "fixture",
            "type": "openai",
            "skip_model_discovery": True,
            "config": connection,
            "allowed_models": [{
                "name": "fixture-model",
                "provider_model_id": "fixture-model",
                "model_type": "llm",
            }],
        }],
    }
    typed = InferenceConfiguration.model_validate(inference)
    runtime_provider = OpenAIInferenceProvider(typed.providers[0])._build_provider()
    minimal = {
        "inference": inference,
        "ogx": {"config": {"baseline": "empty"}},
    }
    typed_only = synthesize_configuration(copy.deepcopy(minimal))

    native_input = copy.deepcopy(minimal)
    native_input["ogx"]["config"]["native_override"] = {
        "providers": {"inference": [{
            "provider_id": "fixture",
            "provider_type": "remote::openai",
            "config": {**connection, "allowed_models": ["fixture-model"]},
        }]}
    }
    native = synthesize_configuration(native_input)

    legacy_input = copy.deepcopy(minimal)
    legacy_entry = legacy_input["inference"]["providers"][0]
    legacy_entry["extra"] = copy.deepcopy(connection)
    # Keep config too, showing why both runtime consumers require settings in
    # this revision. Supplying extra alone would leave typed config empty.
    legacy = synthesize_configuration(legacy_input)

    replacement_input = copy.deepcopy(minimal)
    replacement_input["ogx"]["config"]["native_override"] = {
        "registered_resources": {"models": []}
    }
    replacement = synthesize_configuration(replacement_input)
    expected_model = {
        "model_id": "fixture-model",
        "model_type": "llm",
        "provider_id": "fixture",
        "provider_model_id": "fixture-model",
    }
    assert typed_only["providers"]["inference"][0]["config"] == {
        "allowed_models": ["fixture-model"]
    }
    assert typed_only["registered_resources"]["models"] == [expected_model]
    assert native["providers"]["inference"][0]["config"] == {
        **connection, "allowed_models": ["fixture-model"]
    }
    assert legacy["providers"]["inference"] == native["providers"]["inference"]
    assert replacement["registered_resources"]["models"] == []
    print(json.dumps({
        "source_revision": "7693565545044173814b1c5ad5aa66dd329e8b34",
        "probe_kind": "independent_runtime_configuration_synthesis_no_network",
        "typed_config_input": minimal,
        "typed_model_accepts_connection": {
            "api_key": typed.providers[0].config.api_key.get_secret_value(),
            "base_url": typed.providers[0].config.base_url,
        },
        "native_pydantic_ai_provider_receives": {
            "api_key": runtime_provider.client.api_key,
            "base_url": str(runtime_provider.client.base_url),
        },
        "typed_config_only_synthesis": typed_only,
        "typed_plus_native_override_synthesis": native,
        "typed_plus_deprecated_extra_synthesis": legacy,
        "explicit_empty_models_override_synthesis": replacement,
        "assertions_passed": True,
        "conclusions": {
            "typed_connection_forwarding": (
                "Confirmed inconsistency in this pinned revision: typed config is "
                "accepted and used by the native Pydantic AI provider, while OGX "
                "synthesis ignores it and reads only legacy extra/api_key_env. "
                "This is not an unknown-field input error. Runtime service/model "
                "effects are established separately from this isolated probe."
            ),
            "documented_workaround": (
                "Keep typed connection settings for the native provider and duplicate "
                "the OGX inference provider connection in the documented native_override. "
                "The deprecated extra escape hatch also forwards to OGX, but is not "
                "the preferred new setup."
            ),
            "models_override": (
                "An explicit registered_resources.models list under native_override "
                "replaces auto-registered models. The empty override causing loss "
                "of fixture-model was experiment configuration error, not a product bug."
            ),
        },
        "source_evidence": [
            "src/models/config.py:779 typed OpenAI connection fields",
            "src/models/config.py:932 api_key_env and extra deprecated in favor of config",
            "src/providers/inference/openai/provider.py:38 uses entry.config",
            "src/client/ogx.py:141 synthesizes from raw YAML input",
            "src/ogx_configuration.py:1197 reads extra and api_key_env; ignores config",
            "src/ogx_configuration.py:1313 documents model list replacement",
            "src/models/config.py:1117 documents native_override list replacement",
            "docs/user_doc/config.md:708 recommends config.api_key over api_key_env",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
