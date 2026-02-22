import re
import yaml
import anthropic
from typing import Tuple, List, Optional
from .examples import FALCO_FIELD_REFERENCE


client = anthropic.Anthropic()
MODEL = "claude-sonnet-4-6"

FALCO_SYSTEM_PROMPT = f"""You are a Falco security expert. Falco is a CNCF graduated cloud-native runtime security tool.
You have deep expertise in writing, explaining, and optimizing Falco rules.

Falco rules are written in YAML and use a custom condition language based on sysdig filter expressions.

{FALCO_FIELD_REFERENCE}

## Rule Structure
```yaml
- rule: <rule_name>
  desc: <description>
  condition: <condition_expression>
  output: <output_format_string>
  priority: <EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|DEBUG>
  tags: [<tag1>, <tag2>]
```

## Macros (reusable conditions)
```yaml
- macro: container
  condition: (container.id != host)
```

## Lists (reusable value sets)
```yaml
- list: shell_binaries
  items: [bash, sh, zsh, ksh, fish]
```

Always produce syntactically valid Falco YAML. Include macros and lists when they improve readability.
Use MITRE ATT&CK tags (e.g., mitre_execution, mitre_persistence) when applicable.
"""

GENERATE_PROMPT_TEMPLATE = """Generate a complete, production-ready Falco rule for the following security requirement:

**Security Requirement**: {description}
**Deployment Context**: {context}
**Desired Severity**: {severity}
**Additional Tags**: {tags}

Requirements:
1. Output ONLY valid Falco YAML (no markdown code blocks, no extra text)
2. Include any necessary macros and lists before the rule
3. Make conditions specific enough to minimize false positives
4. Add MITRE ATT&CK tags where applicable
5. Use descriptive output strings with relevant field interpolations
6. Add comments explaining non-obvious condition logic

Produce a complete, copy-paste ready Falco rule file."""

EXPLAIN_PROMPT_TEMPLATE = """Explain the following Falco rule(s) in clear, accessible language for a DevOps engineer who may not be a security expert.

**Falco Rule YAML**:
```yaml
{rule_yaml}
```

Provide your explanation in this exact structure:
## What This Rule Does
[Plain English explanation of the security behavior being detected]

## When It Triggers
[Specific conditions that would cause an alert]

## Why It Matters (Security Impact)
[The attack scenarios or risks this protects against, with MITRE ATT&CK references if applicable]

## Example Alert Output
[Show what an actual Falco alert from this rule might look like]

## Tuning Recommendations
[How to customize the rule to reduce false positives or expand coverage]"""

VALIDATE_PROMPT_TEMPLATE = """Analyze this Falco rule YAML for correctness and best practices:

```yaml
{rule_yaml}
```

Check for:
1. YAML syntax validity
2. Required fields (rule, desc, condition, output, priority)
3. Valid priority levels
4. Condition syntax correctness
5. Output string field reference validity
6. Best practice violations

Respond in this EXACT JSON format (no markdown, just raw JSON):
{{
  "valid": true/false,
  "errors": ["error1", "error2"],
  "warnings": ["warning1", "warning2"],
  "suggestions": ["suggestion1", "suggestion2"],
  "score": 0-100
}}"""

OPTIMIZE_PROMPT_TEMPLATE = """Review and optimize this Falco rule for performance and effectiveness:

```yaml
{rule_yaml}
```

Analyze:
1. **Performance**: Are there expensive condition checks that could be reordered or simplified?
2. **False Positives**: Are conditions too broad? Suggest more specific filters.
3**Coverage**: Are there gaps in detection coverage?
4. **Style**: Does it follow Falco community conventions?

Then provide:
1. The optimized rule YAML
2. A summary of changes made

Format your response as:
### Optimized Rule
```yaml
[optimized yaml here]
```

### Changes Made
- [change 1]
- [change 2]"""


def generate_rule(
    description: str,
    context: str = "Kubernetes environment",
    severity: str = "WARNING",
    tags: List[str] = [],
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Generate a Falco rule from natural language description.
    Returns: (success, rule_yaml, error_message)
    """
    tags_str = ", ".join(tags) if tags else "none specified"
    prompt = GENERATE_PROMPT_TEMPLATE.format(
        description=description,
        context=context,
        severity=severity,
        tags=tags_str,
    )

    message = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        system=FALCO_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()

    # Strip markdown code fences if model wraps output
    cleaned = re.sub(r"^```(?:yaml)?\n?", "", raw)
    cleaned = re.sub(r"\n?```$", "", cleaned)
    cleaned = cleaned.strip()

    return True, cleaned, None


def explain_rule(rule_yaml: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Explain a Falco rule in plain English.
    Returns: (success, explanation, error_message)
    """
    prompt = EXPLAIN_PROMPT_TEMPLATE.format(rule_yaml=rule_yaml)

    message = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        system=FALCO_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return True, message.content[0].text.strip(), None


def validate_rule(rule_yaml: str) -> Tuple[bool, dict]:
    """
    Validate a Falco rule for syntax and best practices.
    Returns: (success, validation_result_dict)
    """
    # First do a quick YAML parse check
    pre_errors = []
    try:
        parsed = yaml.safe_load(rule_yaml)
        if not isinstance(parsed, list):
            pre_errors.append("Rule file must be a YAML list (starting with '-')")
        else:
            for item in parsed:
                if isinstance(item, dict) and "rule" in item:
                    for required in ["desc", "condition", "output", "priority"]:
                        if required not in item:
                            pre_errors.append(
                                f"Rule '{item.get('rule', 'unknown')}' missing required field: '{required}'"
                            )
                    priority = item.get("priority", "")
                    valid_priorities = [
                        "EMERGENCY", "ALERT", "CRITICAL", "ERROR",
                        "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"
                    ]
                    if priority and priority.upper() not in valid_priorities:
                        pre_errors.append(
                            f"Invalid priority '{priority}'. Must be one of: {', '.join(valid_priorities)}"
                        )
    except yaml.YAMLError as e:
        return False, {
            "valid": False,
            "errors": [f"YAML parse error: {str(e)}"],
            "warnings": [],
            "suggestions": [],
            "score": 0,
        }

    prompt = VALIDATE_PROMPT_TEMPLATE.format(rule_yaml=rule_yaml)

    message = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=FALCO_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    import json
    raw = message.content[0].text.strip()
    # Strip markdown if present
    raw = re.sub(r"^```(?:json)?\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)

    result = json.loads(raw)

    # Merge any pre-validation errors
    if pre_errors:
        result["errors"] = pre_errors + result.get("errors", [])
        result["valid"] = False

    return True, result


def optimize_rule(rule_yaml: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Suggest optimizations for a Falco rule.
    Returns: (success, optimized_content, error_message)
    """
    prompt = OPTIMIZE_PROMPT_TEMPLATE.format(rule_yaml=rule_yaml)

    message = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        system=FALCO_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return True, message.content[0].text.strip(), None


def chat_with_falco_expert(message: str, history: list) -> str:
    """
    Multi-turn conversation with the Falco AI expert.
    """
    messages = []
    for h in history:
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": message})

    response = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        system=FALCO_SYSTEM_PROMPT
        + "\n\nYou are also acting as an interactive assistant. Help users understand Falco, write rules, debug issues, and learn security best practices.",
        messages=messages,
    )

    return response.content[0].text.strip()
