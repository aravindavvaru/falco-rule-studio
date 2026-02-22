from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pathlib import Path
import os

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

from .models import (
    GenerateRuleRequest,
    ExplainRuleRequest,
    ValidateRuleRequest,
    OptimizeRuleRequest,
    RuleResponse,
    ChatRequest,
)
from .rule_engine import (
    generate_rule,
    explain_rule,
    validate_rule,
    optimize_rule,
    chat_with_falco_expert,
)
from .examples import EXAMPLE_RULES, EXAMPLE_PROMPTS

app = FastAPI(
    title="Falco Rule Studio",
    description="AI-powered Falco security rule generator, explainer, and validator — a missing feature in the CNCF Falco ecosystem.",
    version="1.0.0",
)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    msg = str(exc)
    if "api_key" in msg.lower() or "authentication" in msg.lower() or "auth_token" in msg.lower():
        return JSONResponse(
            status_code=401,
            content={"detail": "ANTHROPIC_API_KEY is not set. Add it to your .env file or export it as an environment variable."},
        )
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {msg}"})

STATIC_DIR = Path(__file__).parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/examples")
async def get_examples():
    """Return example rules and prompts for the UI."""
    return {
        "rules": EXAMPLE_RULES,
        "prompts": EXAMPLE_PROMPTS,
    }


@app.post("/api/generate", response_model=RuleResponse)
async def api_generate_rule(request: GenerateRuleRequest):
    """
    Convert a natural language security description into a valid Falco rule.
    This is the core missing feature: no existing Falco tooling can do this.
    """
    if not request.description.strip():
        raise HTTPException(status_code=400, detail="Description cannot be empty")

    success, rule_yaml, error = generate_rule(
        description=request.description,
        context=request.context or "Kubernetes environment",
        severity=request.severity or "WARNING",
        tags=request.tags or [],
    )

    if not success:
        return RuleResponse(success=False, errors=[error])

    return RuleResponse(success=True, rule_yaml=rule_yaml)


@app.post("/api/explain", response_model=RuleResponse)
async def api_explain_rule(request: ExplainRuleRequest):
    """
    Explain a Falco rule in plain English.
    Helps teams understand what existing rules actually detect.
    """
    if not request.rule_yaml.strip():
        raise HTTPException(status_code=400, detail="Rule YAML cannot be empty")

    success, explanation, error = explain_rule(request.rule_yaml)

    if not success:
        return RuleResponse(success=False, errors=[error])

    return RuleResponse(success=True, explanation=explanation)


@app.post("/api/validate", response_model=RuleResponse)
async def api_validate_rule(request: ValidateRuleRequest):
    """
    Validate a Falco rule for correctness, completeness, and best practices.
    Catches issues before they reach production.
    """
    if not request.rule_yaml.strip():
        raise HTTPException(status_code=400, detail="Rule YAML cannot be empty")

    success, result = validate_rule(request.rule_yaml)

    if not success:
        return RuleResponse(success=False, errors=["Validation service error"])

    return RuleResponse(
        success=result.get("valid", False),
        errors=result.get("errors", []),
        warnings=result.get("warnings", []),
        suggestions=result.get("suggestions", []),
    )


@app.post("/api/optimize", response_model=RuleResponse)
async def api_optimize_rule(request: OptimizeRuleRequest):
    """
    Analyze and optimize an existing Falco rule for performance and accuracy.
    Reduces false positives and improves detection quality.
    """
    if not request.rule_yaml.strip():
        raise HTTPException(status_code=400, detail="Rule YAML cannot be empty")

    success, result, error = optimize_rule(request.rule_yaml)

    if not success:
        return RuleResponse(success=False, errors=[error])

    return RuleResponse(success=True, explanation=result)


@app.post("/api/chat")
async def api_chat(request: ChatRequest):
    """
    Multi-turn chat with a Falco AI expert.
    Ask questions, get help debugging rules, or learn about Falco internals.
    """
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    history = [{"role": m.role, "content": m.content} for m in (request.history or [])]
    response = chat_with_falco_expert(request.message, history)

    return {"response": response}


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Falco Rule Studio"}
