import runpy
from pathlib import Path

remote_task_id = runpy.run_path(
    str(Path(__file__).parents[1] / "scripts/mas_workflow.py")
)["remote_task_id"]


def result(task_id):
    return {"execution_metadata": {"remote_agent": True, "a2a_task_id": task_id}}


def test_current_turn_record_is_selected_from_a_reused_chat():
    graph = {
        "inter_packets": [
            {"payload": {"result": result("old-task")}},
            {"payload": {"result": result("current-task")}},
        ],
        "workspaces": {"older-context": {"results": [result("old-task")]}},
    }
    assert remote_task_id(graph) == "current-task"


def test_single_turn_remote_record_remains_supported():
    assert remote_task_id({"result": result("only-task")}) == "only-task"
    assert remote_task_id({"result": {}}) is None
