#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml
from google import genai
from google.genai import types

TRACE: list[dict[str, Any]] = []
BASE_URL = ""
ALLOWED_PATH_PREFIXES = ("/health", "/contracts.json", "/tests", "/receipts/")

def now() -> str: return datetime.now(timezone.utc).isoformat()

def safe_url(value: str) -> str:
    base = urllib.parse.urlparse(BASE_URL)
    value = value.strip()
    parsed = urllib.parse.urlparse(value if value.startswith(("http://", "https://")) else BASE_URL.rstrip("/") + "/" + value.lstrip("/"))
    if parsed.scheme != "https": raise ValueError("Only HTTPS is allowed")
    if parsed.netloc != base.netloc: raise ValueError("Host outside TRUSTCHECK_URL")
    if not any(parsed.path == p or parsed.path.startswith(p) for p in ALLOWED_PATH_PREFIXES):
        raise ValueError(f"Path not allowed: {parsed.path}")
    return urllib.parse.urlunparse(parsed)

def request(method: str, path_or_url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    url = safe_url(path_or_url)
    req = urllib.request.Request(url, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type":"application/json","User-Agent":"trustcheck-agent-runner/1.0"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except Exception as e:
        result = {"ok":False,"method":method,"url":url,"status":None,"error":type(e).__name__,"message":str(e),"latency_ms":round((time.perf_counter()-started)*1000,2)}
        TRACE.append({"timestamp":now(),"request_body":body,**result}); return result
    try: payload = json.loads(raw)
    except json.JSONDecodeError: payload = {"raw_text":raw.decode("utf-8","replace")[:1000]}
    result = {"ok":200 <= status < 300,"method":method,"url":url,"status":status,"data":payload,"latency_ms":round((time.perf_counter()-started)*1000,2)}
    TRACE.append({"timestamp":now(),"request_body":body,**result}); return result

def trustcheck_get(path_or_url: str) -> dict[str, Any]:
    """HTTP GET against TrustCheck only. Use /contracts.json or /tests/{test_id}."""
    return request("GET", path_or_url)

def trustcheck_post(path_or_url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """HTTP POST against TrustCheck only. Use /tests or /receipts/{id}/verify."""
    return request("POST", path_or_url, body or {})

def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f: return yaml.safe_load(f)

def prompt(skill: str, s: dict[str, Any]) -> str:
    v=s["visible"]
    return f'''You are a fresh autonomous agent evaluated on using a service from SKILL.md alone.
Follow SKILL.md exactly. Use the supplied HTTP tools. Do not inspect files or hidden data.
Do not infer behavior from the target identifier. Do not ask questions. Execute calls, do not merely describe them.
Return only the final format required by SKILL.md.

TRUSTCHECK_URL = {BASE_URL}

target_id: {v['target_id']}
endpoint: {v['endpoint']}
declared_version: {v['declared_version']}
consent_token: {v['consent_token']}
required_capability: {v['required_capability']}

SKILL.md
--------
{skill}
'''

def evaluate(s: dict[str, Any], final_text: str) -> dict[str, Any]:
    expected=s["hidden_expected"]
    gets=[x for x in TRACE if x.get("method")=="GET" and urllib.parse.urlparse(x["url"]).path.endswith("/contracts.json")]
    tests=[x for x in TRACE if x.get("method")=="POST" and urllib.parse.urlparse(x["url"]).path=="/tests"]
    verifies=[x for x in TRACE if x.get("method")=="POST" and urllib.parse.urlparse(x["url"]).path.startswith("/receipts/") and urllib.parse.urlparse(x["url"]).path.endswith("/verify")]
    td=tests[-1].get("data",{}) if tests else {}; vd=verifies[-1].get("data",{}) if verifies else {}
    body=tests[-1].get("request_body",{}) if tests else {}; target=body.get("target",{}) if isinstance(body,dict) else {}
    checks={
      "contracts_called":bool(gets),
      "correct_contract_selected":body.get("contract_id")=="invoice.extract-total.v1",
      "valid_target_request":target.get("target_id")==s["visible"]["target_id"] and target.get("endpoint")==s["visible"]["endpoint"] and target.get("declared_version")==s["visible"]["declared_version"] and target.get("consent_token")==s["visible"]["consent_token"],
      "test_called":bool(tests),
      "actual_verdict_correct":td.get("verdict")==expected["verdict"],
      "receipt_verify_called":bool(verifies),
      "receipt_valid":vd.get("valid") is True,
      "final_text_contains_status":expected["verdict"] in final_text,
      "final_text_contains_action":expected["action"] in final_text,
      "no_question_mark":"?" not in final_text,
    }
    success=all(checks.values())
    if success: classification="SUCCESS"
    elif not tests and any(x.get("status") is None for x in TRACE): classification="ENVIRONMENT_BLOCKED"
    else: classification="SKILL_FAILURE"
    return {"classification":classification,"success":success,"expected":expected,"observed":{"verdict":td.get("verdict"),"recommended_action":(td.get("recommended_action") or {}).get("action"),"receipt_valid":vd.get("valid")},"checks":checks}

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--scenario",required=True,choices=["alpha","beta"]); p.add_argument("--model",default=os.getenv("MODEL_ID","gemini-2.5-flash")); p.add_argument("--project",default=os.getenv("GOOGLE_CLOUD_PROJECT")); p.add_argument("--location",default=os.getenv("GOOGLE_CLOUD_LOCATION","us-central1")); p.add_argument("--skill",default="SKILL.md"); p.add_argument("--scenarios",default="COLD-AGENT-SCENARIOS.yaml"); p.add_argument("--results",default="COLD-AGENT-RESULTS.yaml"); a=p.parse_args()
    if not a.project: print("ERROR: GOOGLE_CLOUD_PROJECT not set",file=sys.stderr); return 2
    global BASE_URL
    doc=load_yaml(Path(a.scenarios)); BASE_URL=doc["trustcheck_url"].rstrip("/"); s=next(x for x in doc["scenarios"] if x["scenario_id"]==a.scenario)
    skill=Path(a.skill).read_text(encoding="utf-8")
    client=genai.Client(vertexai=True,project=a.project,location=a.location)
    response=client.models.generate_content(model=a.model,contents=prompt(skill,s),config=types.GenerateContentConfig(
    temperature=0,
    system_instruction=(
        "Execute the requested TrustCheck workflow autonomously. "
        "You have working HTTP tools. "
        "Do not claim the environment is blocked unless a tool call "
        "returns a real network error. "
        "You must begin by calling trustcheck_get for /contracts.json. "
        "Then submit the test and verify its receipt. "
        "Do not ask the user questions."
    ),
    tools=[trustcheck_get, trustcheck_post],
    tool_config=types.ToolConfig(
        function_calling_config=types.FunctionCallingConfig(
            mode="ANY",
            allowed_function_names=[
                "trustcheck_get",
                "trustcheck_post",
            ],
        )
    ),
    automatic_function_calling=types.AutomaticFunctionCallingConfig(
        maximum_remote_calls=12
    ),
),
    run={"run_id":f"vertex-{a.model}-{a.scenario}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}","timestamp":now(),"agent":"Vertex AI Gemini controlled runner","model":a.model,"scenario":a.scenario,"fresh_session":True,"final_response":text,"tool_trace":TRACE,**ev}
    rp=Path(a.results); results=load_yaml(rp) if rp.exists() else {}; results=results or {}; results.setdefault("project","TrustCheck"); results.setdefault("spike","cold-agent-skill-validation"); results.setdefault("runs",[]); results["runs"].append(run); results["updated_at"]=now()
    counts={k:0 for k in ("SUCCESS","SKILL_FAILURE","ENVIRONMENT_BLOCKED")}
    for r in results["runs"]:
        c=r.get("classification") or r.get("status")
        if c in counts: counts[c]+=1
    results["cold_agent_summary"]={"success":counts["SUCCESS"],"skill_failure":counts["SKILL_FAILURE"],"environment_blocked":counts["ENVIRONMENT_BLOCKED"],"required_success_runs":6}
    with rp.open("w",encoding="utf-8") as f: yaml.safe_dump(results,f,sort_keys=False,allow_unicode=True)
    trace=Path(f"run-{a.scenario}-{int(time.time())}.json"); trace.write_text(json.dumps(run,indent=2,ensure_ascii=False),encoding="utf-8")
    print("\n=== FINAL MODEL RESPONSE ===\n",text); print("\n=== EVALUATION ===\n",yaml.safe_dump(ev,sort_keys=False,allow_unicode=True)); print(f"Saved: {rp} and {trace}")
    return 0 if ev["success"] else 1
if __name__=="__main__": raise SystemExit(main())
