from pydantic import BaseModel
from typing import Optional, List


class GenerateRuleRequest(BaseModel):
    description: str
    context: Optional[str] = None  # e.g., "Kubernetes environment", "bare metal"
    severity: Optional[str] = "WARNING"
    tags: Optional[List[str]] = []


class ExplainRuleRequest(BaseModel):
    rule_yaml: str


class ValidateRuleRequest(BaseModel):
    rule_yaml: str


class OptimizeRuleRequest(BaseModel):
    rule_yaml: str


class RuleResponse(BaseModel):
    success: bool
    rule_yaml: Optional[str] = None
    explanation: Optional[str] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    suggestions: Optional[List[str]] = None


class ChatMessage(BaseModel):
    role: str  # "user" or "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = []
