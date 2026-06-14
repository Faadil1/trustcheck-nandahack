#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from google import genai
from google.genai import types

BASE_URL = ""
TRACE: list[dict[str, Any]] = []


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_url(value: str) -> str:
    base = urllib.parse.urlparse(BASE_URL)
    if not value.startswith("http"):
        value = BASE_URL.rstrip("/") + "/" + value.lstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.netloc != base.netloc:
        raise ValueError("Only the configured TrustCheck HTTPS host is allowed.")
    allowed = ("/contracts.json", "/tests", "/receipts/")
    if not any(parsed.path == p or parsed.path.startswith(p) for p in allowed):
        raise ValueError(f"Path not allowed: {parsed.path}")
    return value


def http_call(method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    url = safe_url(url)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "User-Agent": "trustcheck-runner-v2/1.0"},
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = resp.status
    except Exception as exc:
        result = {
            "ok": False,
            "method": method,
            "url": url,
            "error": type(exc).__name__,
            "message": str(exc),
        }
        TRACE.append(result)
        return result
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"raw_text": raw.decode("utf-8", "replace")}
    result = {
        "ok": 200 <= status < 300,
        "method": method,
        "url": url,
        "status": status,
        "data": payload,
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    TRACE.append(result)
    return result


def load_yaml(path: str) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def call_model(client, model: str, contents: str, tools=None, forced_name: str | None = None):
    kwargs: dict[str, Any] = {
        "temperature": 0,
        "system_instruction": (
            "You are executing a controlled TrustCheck evaluation. "
            "Never claim the environment is blocked unless a provided HTTP result contains a real error. "
            "Do not ask questions."
        ),
    }
    if tools:
        kwargs["tools"] = tools
        if forced_name:
            kwargs["tool_config"] = types.ToolConfig(
                function_calling_config=types.FunctionCallingConfig(
                    mode="ANY",
                    allowed_function_names=[forced_name],
                )
            )
        kwargs["automatic_function_calling"] = types.AutomaticFunctionCallingConfig(disable=True)
    return client.models.generate_content(
        model=model,
        contents=contents,
        config=types.GenerateContentConfig(**kwargs),
    )


def extract_call(response) -> tuple[str, dict[str, Any]]:
    for candidate in response.candidates or []:
        for part in candidate.content.parts or []:
            if getattr(part, "function_call", None):
                fc = part.function_call
                return fc.name, dict(fc.args or {})
    raise RuntimeError("The model did not return the required function call.")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", choices=["alpha", "beta"], required=True)
    p.add_argument("--model", default="gemini-2.5-flash")
    p.add_argument("--skill", default="SKILL.md")
    p.add_argument("--scenarios", default="COLD-AGENT-SCENARIOS.yaml")
    p.add_argument("--results", default="COLD-AGENT-RESULTS.yaml")
    args = p.parse_args()

    global BASE_URL
    scenarios = load_yaml(args.scenarios)
    BASE_URL = scenarios["trustcheck_url"].rstrip("/")
    scenario = next(x for x in scenarios["scenarios"] if x["scenario_id"] == args.scenario)
    visible = scenario["visible"]
    expected = scenario["hidden_expected"]
    skill = Path(args.skill).read_text(encoding="utf-8")

    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        client = genai.Client(api_key=api_key)
    else:
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-east1")
        if not project:
            raise SystemExit("Set GOOGLE_CLOUD_PROJECT or GEMINI_API_KEY.")
        client = genai.Client(vertexai=True, project=project, location=location)

    def trustcheck_get(path_or_url: str) -> dict[str, Any]:
        """GET an allowed TrustCheck URL."""
        return {}

    r1 = call_model(
        client,
        args.model,
        f"""Read the SKILL below. Your only next action is to call trustcheck_get
for the published contract catalogue. Use the correct path from the SKILL.

SKILL.md:
{skill}""",
        tools=[trustcheck_get],
        forced_name="trustcheck_get",
    )
    _, a1 = extract_call(r1)
    contracts = http_call("GET", a1["path_or_url"])

    def trustcheck_post(path_or_url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST JSON to an allowed TrustCheck URL."""
        return {}

    r2 = call_model(
        client,
        args.model,
        f"""Using the SKILL, the contract response, and the visible scenario,
your only next action is to call trustcheck_post to submit the behavioral test.
Construct the exact JSON body yourself.

CONTRACT RESPONSE:
{json.dumps(contracts, ensure_ascii=False)}

VISIBLE SCENARIO:
{json.dumps(visible, ensure_ascii=False)}

SKILL.md:
{skill}""",
        tools=[trustcheck_post],
        forced_name="trustcheck_post",
    )
    _, a2 = extract_call(r2)
    test_result = http_call("POST", a2["path_or_url"], a2.get("body") or {})

    r3 = call_model(
        client,
        args.model,
        f"""Using the SKILL and actual TrustCheck result below, your only next
action is to call trustcheck_post on the receipt verification URL. Use an empty
JSON body.

TRUSTCHECK RESULT:
{json.dumps(test_result, ensure_ascii=False)}

SKILL.md:
{skill}""",
        tools=[trustcheck_post],
        forced_name="trustcheck_post",
    )
    _, a3 = extract_call(r3)
    verify_result = http_call("POST", a3["path_or_url"], a3.get("body") or {})

    final = call_model(
        client,
        args.model,
        f"""Return only the exact final result format required by SKILL.md.
Do not ask a question.

VISIBLE SCENARIO:
{json.dumps(visible, ensure_ascii=False)}

ACTUAL TEST RESULT:
{json.dumps(test_result, ensure_ascii=False)}

ACTUAL RECEIPT VERIFICATION:
{json.dumps(verify_result, ensure_ascii=False)}

SKILL.md:
{skill}""",
    ).text or ""

    test_data = test_result.get("data", {})
    verify_data = verify_result.get("data", {})
    submitted = a2.get("body") or {}
    target = submitted.get("target") or {}

    checks = {
        "contracts_called": contracts.get("ok") is True,
        "correct_contract_selected": submitted.get("contract_id") == "invoice.extract-total.v1",
        "valid_target_request": (
            target.get("target_id") == visible["target_id"]
            and target.get("endpoint") == visible["endpoint"]
            and target.get("declared_version") == visible["declared_version"]
            and target.get("consent_token") == visible["consent_token"]
        ),
        "test_called": test_result.get("ok") is True,
        "actual_verdict_correct": test_data.get("verdict") == expected["verdict"],
        "receipt_verify_called": verify_result.get("ok") is True,
        "receipt_valid": verify_data.get("valid") is True,
        "final_text_contains_status": expected["verdict"] in final,
        "final_text_contains_action": expected["action"] in final,
        "no_question_mark": "?" not in final,
    }
    success = all(checks.values())
    classification = "SUCCESS" if success else "SKILL_FAILURE"

    run = {
        "run_id": f"runner-v2-{args.model}-{args.scenario}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "timestamp": now(),
        "agent": "Gemini phased controlled runner v2",
        "model": args.model,
        "scenario": args.scenario,
        "fresh_session": True,
        "classification": classification,
        "success": success,
        "expected": expected,
        "observed": {
            "verdict": test_data.get("verdict"),
            "recommended_action": (test_data.get("recommended_action") or {}).get("action"),
            "receipt_valid": verify_data.get("valid"),
        },
        "checks": checks,
        "final_response": final,
        "tool_trace": TRACE,
    }

    results_path = Path(args.results)
    results = load_yaml(str(results_path)) if results_path.exists() else {"runs": []}
    results.setdefault("runs", []).append(run)
    results["updated_at"] = now()
    results_path.write_text(
        yaml.safe_dump(results, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    trace = Path(f"run-v2-{args.scenario}-{int(time.time())}.json")
    trace.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=== FINAL MODEL RESPONSE ===")
    print(final)
    print("\n=== EVALUATION ===")
    print(
        yaml.safe_dump(
            {
                "classification": classification,
                "success": success,
                "expected": expected,
                "observed": run["observed"],
                "checks": checks,
            },
            sort_keys=False,
            allow_unicode=True,
        )
    )
    print(f"Saved: {results_path} and {trace}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
