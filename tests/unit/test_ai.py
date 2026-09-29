"""AI assistant: redaction, tools, orchestrator loop, drafts, replay, providers and CLI."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from sherlog.ai.orchestrator import (
    confirmed_findings,
    export_run,
    get_run,
    latest_draft,
    list_hypotheses,
    load_replay,
    review_draft,
    run_investigation,
)
from sherlog.ai.providers import (
    AnthropicProvider,
    ChatSession,
    OllamaProvider,
    OpenAICompatibleProvider,
    Provider,
    ProviderError,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    provider_from_config,
)
from sherlog.ai.redact import Redactor, build_redactor, new_secret
from sherlog.ai.tools import ToolContext, ToolError
from sherlog.cli import app
from sherlog.core.case import CaseHandle
from sherlog.core.models import AIRun, AuditEntry, Event, Finding
from sherlog.core.vocab import FindingStatus, VerifiedBy
from sherlog.detection.engine import analyze_case
from sherlog.detection.findings import list_findings, review_finding
from sherlog.intake.service import add_evidence
from sherlog.reporting.context import build_context
from sherlog.reporting.render import render_markdown
from tests.helpers import BRUTE_IP, build_incident

runner = CliRunner()
SECRET = "11" * 32


@pytest.fixture
def analyzed(case: CaseHandle, tmp_path: Path) -> CaseHandle:
    add_evidence(case, build_incident(tmp_path / "evidence"))
    analyze_case(case, gap_threshold=timedelta(hours=6))
    return case


# --- scripted fake model ----------------------------------------------------------------------

Step = Callable[[str | None, list[ToolResult]], Turn]


class Scripted(Provider):
    """A fake model: each step sees what SherLog sent and returns the next turn."""

    name = "scripted"

    def __init__(self, steps: list[Step], draft: str | None = None, model: str = "fake-1") -> None:
        self.model = model
        self.steps = steps
        self.draft = draft
        self.sent: list[str] = []  # every text/tool result that "left the machine"
        self.sessions = 0

    def start(self, system: str, tools: list[ToolSpec]) -> ChatSession:
        self.sessions += 1
        self.sent.append(system)
        outer = self
        is_draft = not tools

        class _S(ChatSession):
            def send(
                self, *, user_text: str | None = None, tool_results: list[ToolResult] | None = None
            ) -> Turn:
                if user_text:
                    outer.sent.append(user_text)
                outer.sent.extend(r.content for r in tool_results or [])
                if is_draft:
                    return Turn(outer.draft or "", [], "end_turn", 100, 50)
                step = (
                    outer.steps.pop(0) if outer.steps else (lambda *_: Turn("done", [], "end_turn"))
                )
                return step(user_text, tool_results or [])

        return _S()


def call(name: str, **args: Any) -> Turn:
    return Turn("", [ToolCall(f"c-{name}", name, args)], "tool_use", 1000, 100)


def last_result(results: list[ToolResult]) -> dict[str, Any]:
    assert results, "expected tool results"
    return json.loads(results[-1].content)


# --- redaction --------------------------------------------------------------------------------


def test_redactor_stable_and_reversible() -> None:
    r = Redactor(SECRET)
    r.add("user", "alice")
    r.add("host", "web01")
    r.add("ip", "10.0.0.5")
    text = "alice logged into web01 from 10.0.0.5; malice and web010 untouched; root stays"
    red = r.redact(text)
    assert "alice logged" not in red and "web01 " not in red and "10.0.0.5" not in red
    assert "malice" in red and "web010" in red and "root stays" in red
    assert r.restore(red) == text
    again = Redactor(SECRET)
    again.add("user", "alice")
    assert again.forward["alice"] == r.forward["alice"]  # stable with the same secret
    other = Redactor(new_secret())
    other.add("user", "alice")
    assert other.forward["alice"] != r.forward["alice"]


def test_redactor_emails_system_accounts_and_disabled() -> None:
    r = Redactor(SECRET)
    r.add("user", "root")
    r.add("user", "www-data")
    assert not r.forward  # generic accounts are kept
    red = r.redact("contact soc@corp.example now")
    assert "soc@corp.example" not in red and "@redacted.invalid" in red
    assert r.restore(red) == "contact soc@corp.example now"
    off = Redactor(SECRET, enabled=False)
    off.add("user", "alice")
    assert off.redact("alice") == "alice" and off.restore_obj({"a": ["alice"]}) == {"a": ["alice"]}


def test_build_redactor_from_case(analyzed: CaseHandle) -> None:
    with analyzed.session() as s:
        r = build_redactor(s, SECRET)
    assert "web01" in r.forward and "backdoor" in r.forward and "deploy" in r.forward
    assert "root" not in r.forward
    assert BRUTE_IP not in r.forward  # only internal (RFC 1918 etc.) addresses are redacted
    r.add("ip", "10.1.2.3")
    assert r.redact("from 10.1.2.3") != "from 10.1.2.3"


# --- tools ------------------------------------------------------------------------------------


def _ctx(case: CaseHandle, **kw: Any) -> ToolContext:
    with case.session() as s:
        run = AIRun(
            started_at=__import__("sherlog.core.timeutil", fromlist=["utcnow"]).utcnow(),
            provider="t",
            model="m",
            redaction=True,
            redaction_secret=SECRET,
            max_iterations=1,
            token_budget=1,
            status="running",
        )
        s.add(run)
        s.flush()
        run_id = run.id
    return ToolContext(case, run_id, "m", **kw)


def test_read_tools(analyzed: CaseHandle) -> None:
    ctx = _ctx(analyzed)
    res = ctx.execute(
        "search_events", {"event_type": "auth.login.failure", "ip": BRUTE_IP, "limit": 5}
    )
    assert res["total_matches"] >= 12 and len(res["events"]) == 5
    assert res["events"][0]["source"].startswith("var/log/auth.log:")
    first = res["events"][0]["time_utc"]
    win = ctx.execute("get_timeline_window", {"start": first, "end": first})
    assert win["events"]
    arts = ctx.execute("list_artifacts", {})
    assert {a["type"] for a in arts["artifacts"]} >= {"linux.auth", "web.access"}
    pivot = ctx.execute("pivot_on_ioc", {"value": BRUTE_IP})
    assert pivot["finding_ids"] and pivot["events"]
    rule = ctx.execute("run_rule", {"rule_id": "5c1e2f9a-0b3d-4a71-9e21-1a0b7c4d1003"})
    assert rule["match_count"] == 1
    with pytest.raises(ToolError):
        ctx.execute("run_rule", {"rule_id": "nope"})
    with pytest.raises(ToolError):
        ctx.execute("search_events", {"text": "("})
    with pytest.raises(ToolError):
        ctx.execute("shell", {"cmd": "id"})


def test_propose_finding_validation(analyzed: CaseHandle) -> None:
    ctx = _ctx(analyzed)
    with pytest.raises(ToolError, match="do not exist"):
        ctx.execute(
            "propose_finding",
            {
                "title": "x",
                "severity": "high",
                "confidence": 0.5,
                "narrative": "y",
                "event_ids": [999999],
            },
        )
    with pytest.raises(ToolError, match="event_ids"):
        ctx.execute(
            "propose_finding",
            {
                "title": "x",
                "severity": "high",
                "confidence": 0.5,
                "narrative": "y",
                "event_ids": [],
            },
        )
    with pytest.raises(ToolError, match="severity"):
        ctx.execute(
            "propose_finding",
            {
                "title": "x",
                "severity": "huge",
                "confidence": 0.5,
                "narrative": "y",
                "event_ids": [1],
            },
        )
    with analyzed.session() as s:
        ids = list(s.scalars(select(Event.id).where(Event.event_type == "shell.command").limit(2)))
    args = {
        "title": "Attacker staged tooling",
        "severity": "high",
        "confidence": 0.7,
        "narrative": "events show it",
        "event_ids": ids,
        "attack_techniques": ["T1105", "T9999"],
    }
    out = ctx.execute("propose_finding", args)
    assert out["dropped_techniques"] == ["T9999"]
    dup = ctx.execute("propose_finding", args)
    assert dup["finding_id"] == out["finding_id"] and "duplicate" in dup["status"]
    with analyzed.session() as s:
        f = s.get(Finding, out["finding_id"])
        assert f is not None and f.verified_by == VerifiedBy.AI_PROPOSED
        assert f.attack_techniques == ["T1105"] and len(f.events) == len(ids)
    hyp = ctx.execute(
        "propose_hypothesis",
        {"statement": "s", "rationale": "r", "supporting_event_ids": [ids[0], 424242]},
    )
    assert hyp["ignored_event_ids"] == [424242]


def test_request_enrichment_policy(analyzed: CaseHandle) -> None:
    with pytest.raises(ToolError, match="offline"):
        _ctx(analyzed, offline=True).execute("request_enrichment", {"ioc": BRUTE_IP})
    ctx = _ctx(analyzed, enrich=lambda v: {"providers": {}})
    with pytest.raises(ToolError, match="privacy policy"):
        ctx.execute("request_enrichment", {"ioc": "backdoor"})  # username: never sent
    with pytest.raises(ToolError, match="Not an extracted IOC"):
        ctx.execute("request_enrichment", {"ioc": "1.1.1.1"})


# --- orchestrator -----------------------------------------------------------------------------


DRAFT = json.dumps(
    {
        "executive_summary": "An attacker brute-forced SSH on host X.",
        "narrative": "First the attacker guessed passwords.",
    }
)


def _investigation_script(case: CaseHandle) -> Scripted:
    seen: dict[str, Any] = {}

    def step1(user_text: str | None, _: list[ToolResult]) -> Turn:
        assert user_text and "web01" not in user_text  # briefing was redacted
        # The model only knows the pseudonym of the backdoor account ("target user-xxxx").
        seen["pseudo"] = re.search(r"target (user-[0-9a-f]{6})", user_text).group(1)  # type: ignore[union-attr]
        return call("search_events", event_type="user.create", text=seen["pseudo"])

    def step2(_: str | None, results: list[ToolResult]) -> Turn:
        res = last_result(results)
        # The pseudonym in the arguments was restored before querying the database...
        assert res["total_matches"] == 1
        # ...and the real name in the result was pseudonymized again before sending.
        assert seen["pseudo"] in res["events"][0]["raw"]
        seen["ids"] = [e["id"] for e in res["events"]]
        return Turn(
            "",
            [
                ToolCall(
                    "p1",
                    "propose_finding",
                    {
                        "title": f"Backdoor account {res['events'][0]['target']} created",
                        "severity": "critical",
                        "confidence": 0.9,
                        "narrative": "Event shows useradd",
                        "event_ids": seen["ids"],
                    },
                ),
                ToolCall(
                    "p2",
                    "propose_finding",
                    {
                        "title": "Invented",
                        "severity": "low",
                        "confidence": 0.1,
                        "narrative": "n",
                        "event_ids": [987654],
                    },
                ),
                ToolCall(
                    "h1",
                    "propose_hypothesis",
                    {"statement": "Initial access was SSH", "rationale": "brute force before"},
                ),
            ],
            "tool_use",
            2000,
            200,
        )

    def step3(_: str | None, results: list[ToolResult]) -> Turn:
        assert results[1].is_error and "do not exist" in results[1].content
        return Turn("Investigation complete.", [], "end_turn", 500, 50)

    return Scripted([step1, step2, step3], draft=DRAFT)


def test_full_run(analyzed: CaseHandle) -> None:
    provider = _investigation_script(analyzed)
    result = run_investigation(analyzed, provider, max_iterations=10)
    assert result["status"] == "completed" and result["iterations"] == 3
    assert len(result["findings_proposed"]) == 1 and len(result["hypotheses"]) == 1
    assert result["draft_id"] and result["final_text"] == "Investigation complete."
    # Nothing identifying left the machine.
    everything = "\n".join(provider.sent)
    for secret_value in ("web01", "backdoor", "deploy"):
        assert secret_value not in everything, secret_value
    # The stored finding uses the real name (pseudonym restored).
    with analyzed.session() as s:
        f = s.get(Finding, result["findings_proposed"][0])
        assert f is not None and "backdoor" in f.title and f.status == FindingStatus.OPEN
        entry = s.scalars(select(AuditEntry).where(AuditEntry.action == "ai.investigate")).one()
        assert entry.details["tool_calls"][0]["name"] == "search_events"
    run = get_run(analyzed, result["run_id"])
    roles = [m["role"] for m in run["messages"]]
    assert roles[:2] == ["system", "user"] and "tool" in roles and roles[-1] == "draft_response"
    assert list_hypotheses(analyzed)[0]["statement"] == "Initial access was SSH"


def test_draft_uses_only_confirmed_findings(analyzed: CaseHandle) -> None:
    result = run_investigation(analyzed, _investigation_script(analyzed))
    ai_id = result["findings_proposed"][0]
    confirmed = {f["id"] for f in confirmed_findings(analyzed)}
    assert ai_id not in confirmed
    draft = latest_draft(analyzed)
    assert draft and ai_id not in draft["finding_ids"] and draft["status"] == "draft"
    # Accepting the AI finding makes it analyst-verified and eligible next time.
    review_finding(analyzed, ai_id, FindingStatus.ACCEPTED)
    assert ai_id in {f["id"] for f in confirmed_findings(analyzed)}


def test_limits_and_errors(analyzed: CaseHandle) -> None:
    looping = Scripted([lambda *_: call("list_artifacts")] * 10)
    r = run_investigation(analyzed, looping, max_iterations=2)
    assert r["status"] == "stopped" and "iteration limit" in r["stop_reason"]
    budget = Scripted([lambda *_: call("list_artifacts")] * 10)
    r = run_investigation(analyzed, budget, token_budget=1500)
    assert r["status"] == "stopped" and "token budget" in r["stop_reason"]

    def boom(*_: Any) -> Turn:
        raise ProviderError("Anthropic rate limit reached")

    r = run_investigation(analyzed, Scripted([boom]))
    assert r["status"] == "error" and "rate limit" in r["stop_reason"]
    with analyzed.session() as s:
        assert s.get(AIRun, r["run_id"]).status == "error"  # type: ignore[union-attr]


def test_replay_is_reproducible(analyzed: CaseHandle, tmp_path: Path, case: CaseHandle) -> None:
    first = run_investigation(analyzed, _investigation_script(analyzed))
    exported = export_run(analyzed, first["run_id"])
    assert exported["turns"] and exported["redaction_secret"]
    path = tmp_path / "t.json"
    path.write_text(json.dumps(exported))

    provider, opts, label = load_replay(analyzed, str(first["run_id"]))
    again = run_investigation(analyzed, provider, replay_of=label, **opts)
    assert again["status"] == "completed"
    assert again["findings_proposed"] == first["findings_proposed"]  # deduplicated: same finding
    titles = sorted(f["title"] for f in list_findings(analyzed, verified_by=VerifiedBy.AI_PROPOSED))
    assert len(titles) == 1


def test_draft_review_and_report(analyzed: CaseHandle) -> None:
    run_investigation(analyzed, _investigation_script(analyzed))
    draft = latest_draft(analyzed)
    assert draft is not None
    md = render_markdown(build_context(analyzed, verify=False))
    assert "An attacker brute-forced" not in md  # not accepted yet
    assert "Appendix C" in md and "Initial access was SSH" in md
    accepted = review_draft(
        analyzed, draft["id"], "accepted", executive_summary="Edited summary by the analyst."
    )
    assert accepted["edited"] and accepted["status"] == "accepted"
    md = render_markdown(build_context(analyzed, verify=False))
    assert "Edited summary by the analyst." in md and "1.1 Incident narrative" in md
    assert "Key facts (generated automatically)" in md
    review_draft(analyzed, draft["id"], "rejected")
    assert latest_draft(analyzed, status="accepted") is None


# --- providers --------------------------------------------------------------------------------


class FakeMessages:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(json.loads(json.dumps(kwargs, default=lambda o: vars(o))))
        return self.responses.pop(0)


def _resp(content: list[Any], stop: str = "end_turn") -> Any:
    usage = SimpleNamespace(
        input_tokens=10, output_tokens=5, cache_creation_input_tokens=0, cache_read_input_tokens=90
    )
    return SimpleNamespace(content=content, stop_reason=stop, usage=usage, stop_details=None)


def test_anthropic_provider_request_shape() -> None:
    tool_use = SimpleNamespace(type="tool_use", id="tu1", name="list_artifacts", input={})
    messages = FakeMessages(
        [
            _resp([SimpleNamespace(type="text", text="Looking."), tool_use], "tool_use"),
            _resp([SimpleNamespace(type="text", text="Done.")]),
        ]
    )
    provider = AnthropicProvider(client=SimpleNamespace(messages=messages))
    assert provider.model == "claude-sonnet-4-6"
    spec = ToolSpec("list_artifacts", "d", {"type": "object", "properties": {}})
    session = provider.start("sys", [spec])
    turn = session.send(user_text="hello")
    assert turn.tool_calls[0].name == "list_artifacts" and turn.input_tokens == 100
    first = messages.calls[0]
    assert first["model"] == "claude-sonnet-4-6" and first["max_tokens"] == 16000
    assert first["thinking"] == {"type": "adaptive"}
    assert first["cache_control"] == {"type": "ephemeral"}
    assert first["tools"][0]["input_schema"] == {"type": "object", "properties": {}}
    turn2 = session.send(tool_results=[ToolResult("tu1", "{}")])
    assert turn2.text == "Done." and not turn2.tool_calls
    second = messages.calls[1]["messages"]
    assert second[1]["role"] == "assistant"  # full assistant content passed back
    assert second[2]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "tu1",
        "content": "{}",
        "is_error": False,
    }


def test_anthropic_refusal_and_haiku() -> None:
    refused = SimpleNamespace(
        content=[],
        stop_reason="refusal",
        usage=None,
        stop_details=SimpleNamespace(category="cyber"),
    )
    provider = AnthropicProvider(client=SimpleNamespace(messages=FakeMessages([refused])))
    with pytest.raises(ProviderError, match="declined"):
        provider.start("s", []).send(user_text="x")
    haiku = AnthropicProvider("claude-haiku-4-5", client=SimpleNamespace(messages=FakeMessages([])))
    assert haiku.thinking is False


def test_openai_compatible_and_ollama() -> None:
    sent: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    def post(
        url: str, headers: dict[str, str], body: dict[str, Any], timeout: float
    ) -> tuple[int, Any]:
        sent.append((url, headers, json.loads(json.dumps(body))))
        if len(sent) == 1:
            msg = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "search_events", "arguments": '{"actor": "user-abc"}'},
                    }
                ],
            }
            return 200, {
                "choices": [{"message": msg, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            }
        return 200, {
            "choices": [
                {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
            ]
        }

    p = OpenAICompatibleProvider(
        "my-model", base_url="https://llm.example/v1/", api_key="k", http_post=post
    )
    s = p.start("sys", [ToolSpec("search_events", "d", {"type": "object"})])
    t = s.send(user_text="go")
    assert t.tool_calls[0].arguments == {"actor": "user-abc"} and t.input_tokens == 7
    s.send(tool_results=[ToolResult("call_1", "[]")])
    url, headers, body = sent[1]
    assert (
        url == "https://llm.example/v1/chat/completions" and headers["Authorization"] == "Bearer k"
    )
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][-1] == {"role": "tool", "tool_call_id": "call_1", "content": "[]"}
    assert body["tools"][0]["function"]["name"] == "search_events"

    o = OllamaProvider(
        "llama3.1", host="http://localhost:11434", http_post=lambda *a: (500, {"error": "x"})
    )
    assert o.base_url == "http://localhost:11434/v1"
    with pytest.raises(ProviderError, match="500"):
        o.start("s", []).send(user_text="x")


def test_provider_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    assert provider_from_config() is None
    with pytest.raises(ProviderError, match="Unknown AI provider"):
        provider_from_config("gemini")
    with pytest.raises(ProviderError, match="model"):
        provider_from_config("openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    p = provider_from_config("anthropic")
    assert isinstance(p, AnthropicProvider) and p.model == "claude-sonnet-4-6"


# --- CLI --------------------------------------------------------------------------------------


def test_cli_ai_commands(
    tmp_path: Path, analyzed: CaseHandle, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases = str(analyzed.directory.parent)
    base = ["--cases-dir", cases]
    r = runner.invoke(app, [*base, "investigate", "test-case"])
    assert r.exit_code != 0 and "No AI provider configured" in r.output
    r = runner.invoke(app, [*base, "analyze", "test-case", "--json"])
    assert json.loads(r.output)["ai"]["skipped"] == "no provider configured"
    r = runner.invoke(app, [*base, "investigate", "test-case", "--offline"])
    assert r.exit_code != 0

    run = run_investigation(analyzed, _investigation_script(analyzed))
    out = tmp_path / "run.json"
    r = runner.invoke(app, [*base, "ai", "export", "test-case", str(run["run_id"]), "-o", str(out)])
    assert r.exit_code == 0 and out.stat().st_mode & 0o777 == 0o600
    r = runner.invoke(app, [*base, "investigate", "test-case", "--replay", str(out), "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["status"] == "completed"
    r = runner.invoke(app, [*base, "ai", "runs", "test-case", "--json"])
    assert len(json.loads(r.output)) == 2
    r = runner.invoke(app, [*base, "ai", "show", "test-case", str(run["run_id"])])
    assert r.exit_code == 0 and "search_events" in r.output
    r = runner.invoke(app, [*base, "ai", "hypotheses", "test-case"])
    assert "Initial access was SSH" in r.output
    edit = tmp_path / "draft.md"
    r = runner.invoke(app, [*base, "ai", "draft", "test-case", "--write", str(edit)])
    assert r.exit_code == 0 and edit.read_text().startswith("# Executive summary")
    edit.write_text("# Executive summary\n\nReviewed.\n\n# Narrative\n\nStory.\n")
    r = runner.invoke(app, [*base, "ai", "draft", "test-case", "--edit", str(edit), "--json"])
    d = json.loads(r.output)
    assert (
        d["status"] == "accepted"
        and d["executive_summary"] == "Reviewed."
        and d["narrative"] == "Story."
    )
