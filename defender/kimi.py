import json


ALLOWED_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
LIST_FIELDS = ("incident_updates", "capability_updates", "exposure_updates", "defense_scenarios", "watch_conditions", "unresolved_hypotheses", "mitre_attack_context")


SYSTEM_PROMPT = """You are K3DF Defender's analysis component. Analyze only the supplied batch.
You must not execute commands, access files, call tools, modify state, or assume facts not in evidence.
Return JSON only with analysis, incident_updates, capability_updates, exposure_updates,
defense_scenarios, watch_conditions, unresolved_hypotheses, and mitre_attack_context.
Defense scenarios are proposals; express actions as structured objects, never shell commands."""


def validate_result(value):
    if not isinstance(value, dict) or not isinstance(value.get("analysis"), dict):
        raise ValueError("analysis object is required")
    analysis = value["analysis"]
    if analysis.get("threat_level") not in ALLOWED_LEVELS:
        raise ValueError("invalid threat level")
    if not isinstance(analysis.get("summary"), str):
        raise ValueError("analysis summary is required")
    confidence = analysis.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("analysis confidence must be between 0 and 1")
    for field in LIST_FIELDS:
        if field not in value:
            value[field] = []
        if not isinstance(value[field], list):
            raise ValueError("%s must be a list" % field)
        value[field] = value[field][:10]
    return value


class KimiClient:
    def __init__(self, config):
        self.config = config

    def analyze(self, context):
        if not self.config.moonshot_api_key:
            raise RuntimeError("MOONSHOT_API_KEY is not configured")
        from openai import OpenAI

        client = OpenAI(api_key=self.config.moonshot_api_key, base_url=self.config.moonshot_base_url)
        response = client.chat.completions.create(
            model=self.config.moonshot_model,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps(context, ensure_ascii=False)}],
            response_format={"type": "json_object"},
            extra_body={"reasoning_effort": self.config.reasoning_effort},
        )
        return validate_result(json.loads(response.choices[0].message.content))
