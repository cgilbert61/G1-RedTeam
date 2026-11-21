import requests
import json
import logging

logger = logging.getLogger("hybrid_runner.adapters")

class GatewayAdapter:
    def __init__(self, config):
        self.config = config
        self.endpoint = config.get("endpoint", "")
        self.headers = config.get("headers", {})

    def send_prompt(self, prompt: str) -> str:
        raise NotImplementedError("Subclasses must implement send_prompt")

class OpenAIAdapter(GatewayAdapter):
    def send_prompt(self, prompt: str) -> str:
        url = self.endpoint or "http://localhost:8000/v1/chat/completions"
        payload = {
            "model": self.config.get("model_name", "default-model"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.get("temperature", 0.0),
        }
        
        headers = {
            "Content-Type": "application/json",
            **self.headers
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            # Check for security gateway blocks
            if response.status_code in (400, 403, 429, 422):
                body_lower = response.text.lower()
                if response.status_code == 429:
                    return f"Request blocked by security gateway policy: {response.text}"
                if "unauthorized" not in body_lower and "invalid token" not in body_lower and "invalid api key" not in body_lower:
                    if response.status_code in (403, 429) or any(kw in body_lower for kw in ["block", "policy", "security", "violation"]):
                        return f"Request blocked by security gateway policy: {response.text}"
            
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"OpenAI adapter request failed: {e}")
            return f"ERROR: {str(e)}"

class AnthropicAdapter(GatewayAdapter):
    def send_prompt(self, prompt: str) -> str:
        url = self.endpoint or "https://api.anthropic.com/v1/messages"
        payload = {
            "model": self.config.get("model_name", "claude-3-5-sonnet-latest"),
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.config.get("temperature", 0.0),
        }
        
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            **self.headers
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            # Check for security gateway blocks
            if response.status_code in (400, 403, 429, 422):
                body_lower = response.text.lower()
                if response.status_code == 429:
                    return f"Request blocked by security gateway policy: {response.text}"
                if "unauthorized" not in body_lower and "invalid token" not in body_lower and "invalid api key" not in body_lower:
                    if response.status_code in (403, 429) or any(kw in body_lower for kw in ["block", "policy", "security", "violation"]):
                        return f"Request blocked by security gateway policy: {response.text}"
            
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
        except Exception as e:
            logger.error(f"Anthropic adapter request failed: {e}")
            return f"ERROR: {str(e)}"

class CustomJSONAdapter(GatewayAdapter):
    def send_prompt(self, prompt: str) -> str:
        url = self.endpoint
        
        # Parse custom request JSON template if defined, e.g., '{"input_text": "{{PROMPT}}"}'
        req_template_str = self.config.get("request_template", '{"prompt": "{{PROMPT}}"}')
        req_payload_str = req_template_str.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
        
        try:
            payload = json.loads(req_payload_str)
        except Exception as e:
            logger.error(f"Failed to parse custom request payload template: {e}")
            # Fallback to direct dict
            payload = {"prompt": prompt}

        headers = {
            "Content-Type": "application/json",
            **self.headers
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            # Check for security gateway blocks
            if response.status_code in (400, 403, 429, 422):
                body_lower = response.text.lower()
                if response.status_code == 429:
                    return f"Request blocked by security gateway policy: {response.text}"
                if "unauthorized" not in body_lower and "invalid token" not in body_lower and "invalid api key" not in body_lower:
                    if response.status_code in (403, 429) or any(kw in body_lower for kw in ["block", "policy", "security", "violation"]):
                        return f"Request blocked by security gateway policy: {response.text}"
            
            response.raise_for_status()
            data = response.json()

            # Check for Gemini prompt safety blocks
            if "promptFeedback" in data and isinstance(data["promptFeedback"], dict):
                block_reason = data["promptFeedback"].get("blockReason")
                if block_reason:
                    return f"Request blocked by security gateway policy: Prompt safety violation ({block_reason})."

            # Check for Gemini candidate safety blocks
            if "candidates" in data and isinstance(data["candidates"], list) and len(data["candidates"]) > 0:
                candidate = data["candidates"][0]
                if isinstance(candidate, dict):
                    finish_reason = candidate.get("finishReason")
                    if finish_reason and finish_reason != "STOP":
                        return f"Request blocked by security gateway policy: Candidate generation blocked ({finish_reason})."
            
            # Resolve response JSON selector, e.g. "output" or "response.content"
            res_selector = self.config.get("response_selector", "response")
            
            # Simple nested dictionary traversal
            current = data
            for part in res_selector.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list) and part.isdigit():
                    idx = int(part)
                    if 0 <= idx < len(current):
                        current = current[idx]
                    else:
                        raise KeyError(f"Index {idx} out of range in list")
                else:
                    raise KeyError(f"Key/Index {part} not found")
            
            return str(current)
            
        except Exception as e:
            logger.error(f"Custom JSON adapter request failed: {e}")
            return f"ERROR: {str(e)}"

def get_adapter(adapter_type: str, config: dict) -> GatewayAdapter:
    if adapter_type == "openai":
        return OpenAIAdapter(config)
    elif adapter_type == "anthropic":
        return AnthropicAdapter(config)
    elif adapter_type == "custom":
        return CustomJSONAdapter(config)
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")
