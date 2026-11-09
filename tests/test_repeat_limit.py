"""A model that gets stuck repeating itself must end its own task, not the whole run.

F7 (2026-11-09): Ollama aborted one reply with HTTP 500 "prediction aborted, token repeat limit reached"
(workspace user_task_4 x injection_task_9: the model looped while writing a huge email). At temperature 0 the
same reply comes back on every retry, so the exception killed run_batch's 6 attempts and every defense stopped
after 10 of 50 pairs. StopOnRepeatLimit turns that one error into a final assistant message (no tool calls), so
the task ends there, gets logged, and the next pair runs. Any other error is still raised.
"""
import httpx
import openai
import pytest

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, FunctionsRuntime

from mcp_guard.agentdojo_adapter import REPEAT_LIMIT_NOTE, StopOnRepeatLimit, build_pipeline


def server_error(message):
    req = httpx.Request("POST", "http://localhost:11434/v1/chat/completions")
    resp = httpx.Response(500, request=req, json={"error": {"message": message}})
    return openai.InternalServerError(f"Error code: 500 - {message}", response=resp, body=None)


class FailingLLM(BasePipelineElement):
    name = "local-test"

    def __init__(self, message):
        self.message = message
        self.calls = 0

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        self.calls += 1
        raise server_error(self.message)


def test_repeat_limit_ends_the_task_with_a_note():
    llm = FailingLLM("prediction aborted, token repeat limit reached")
    _, _, _, msgs, _ = StopOnRepeatLimit(llm).query("hi", FunctionsRuntime([]), messages=[{"role": "user"}])
    last = msgs[-1]
    assert last["role"] == "assistant" and not last["tool_calls"]
    assert REPEAT_LIMIT_NOTE in last["content"][0]["content"]
    assert llm.calls == 1


def test_other_server_errors_still_raise():
    with pytest.raises(openai.InternalServerError):
        StopOnRepeatLimit(FailingLLM("model crashed")).query("hi", FunctionsRuntime([]))


@pytest.mark.parametrize("defense", ["none", "mcp_guard", "mcp_guard_confirm_oracle"])
def test_pipelines_end_the_task_instead_of_crashing(defense):
    llm = FailingLLM("prediction aborted, token repeat limit reached")
    pipeline, _ = build_pipeline(llm, "local-test", defense)
    _, _, _, msgs, _ = pipeline.query("Send the report to bob", FunctionsRuntime([]))
    assert REPEAT_LIMIT_NOTE in msgs[-1]["content"][0]["content"]


def test_openai_client_does_not_retry_a_repeat_limit_abort():
    """The runner's response hook marks this 500 as not retryable, so the client asks once, not 5 times.
    (AgentDojo's own tenacity retry still tries 3 times; the pipeline then ends the task.)"""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from run_agentdojo import no_retry_on_repeat_limit

    def make(message):
        hits = []

        def handler(request):
            hits.append(1)
            return httpx.Response(500, json={"error": {"message": message}})

        client = openai.OpenAI(api_key="x", base_url="http://ollama.test/v1", max_retries=4,
                               http_client=httpx.Client(transport=httpx.MockTransport(handler),
                                                        event_hooks={"response": [no_retry_on_repeat_limit]}))
        with pytest.raises(openai.InternalServerError):
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
        return len(hits)

    assert make("prediction aborted, token repeat limit reached") == 1
    assert make("something else broke") == 5          # other 500s keep the normal retries
