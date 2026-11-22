import importlib.util
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests

logger = logging.getLogger("hybrid_runner.adapters")


def _check_gateway_block(response: requests.Response) -> Optional[str]:
    """Return a normalized block string if the HTTP response indicates a security gateway block."""
    if response.status_code in (400, 403, 429, 422):
        body_lower = response.text.lower()
        if response.status_code == 429:
            return f"Request blocked by security gateway policy: {response.text}"
        if (
            "unauthorized" not in body_lower
            and "invalid token" not in body_lower
            and "invalid api key" not in body_lower
        ):
            if response.status_code in (403, 429) or any(
                kw in body_lower for kw in ["block", "policy", "security", "violation"]
            ):
                return f"Request blocked by security gateway policy: {response.text}"
    return None


class GatewayAdapter:
    def __init__(self, config: Dict[str, Any]):
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
            **self.headers,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            blocked = _check_gateway_block(response)
            if blocked is not None:
                return blocked

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
            **self.headers,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            blocked = _check_gateway_block(response)
            if blocked is not None:
                return blocked

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
            payload = {"prompt": prompt}

        headers = {
            "Content-Type": "application/json",
            **self.headers,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            blocked = _check_gateway_block(response)
            if blocked is not None:
                return blocked

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

            res_selector = self.config.get("response_selector", "response")

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


class A2AAdapter(GatewayAdapter):
    """Adapter for Google Agent-to-Agent (A2A) JSON-RPC 2.0 HTTP protocol.

    Performs optional Agent Card discovery via ``/.well-known/agent.json``,
    sends prompts using ``message/send``, and preserves G1 gateway block
    detection on HTTP 400/403/422/429 responses.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self._agent_card: Optional[Dict[str, Any]] = None
        self._rpc_url: Optional[str] = None
        self._discovered = False

    def discover_agent_card(self) -> Optional[Dict[str, Any]]:
        """Fetch ``/.well-known/agent.json`` from the target base URL."""
        if self._discovered:
            return self._agent_card
        self._discovered = True

        base = (self.endpoint or "").rstrip("/") + "/"
        if not self.endpoint:
            return None

        card_url = urljoin(base, ".well-known/agent.json")
        headers = {"Accept": "application/json", **self.headers}
        try:
            resp = requests.get(card_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                card = resp.json()
                if isinstance(card, dict):
                    self._agent_card = card
                    if isinstance(card.get("url"), str) and card["url"].strip():
                        self._rpc_url = card["url"].strip()
                    return card
        except Exception as e:
            logger.debug(f"A2A agent card discovery skipped/failed at {card_url}: {e}")
        return None

    @staticmethod
    def _extract_parts_text(parts: Any) -> str:
        if not isinstance(parts, list):
            return ""
        chunks: List[str] = []
        for part in parts:
            if isinstance(part, dict):
                if isinstance(part.get("text"), str):
                    chunks.append(part["text"])
                elif isinstance(part.get("content"), str):
                    chunks.append(part["content"])
        return "\n".join(c for c in chunks if c)

    @classmethod
    def _extract_a2a_text(cls, data: Dict[str, Any]) -> str:
        if "error" in data and isinstance(data["error"], dict):
            err_msg = data["error"].get("message") or json.dumps(data["error"])
            if any(kw in err_msg.lower() for kw in ["block", "policy", "security", "denied"]):
                return f"Request blocked by security gateway policy: {err_msg}"
            return f"ERROR: A2A JSON-RPC error: {err_msg}"

        result = data.get("result")
        if isinstance(result, str):
            return result
        if not isinstance(result, dict):
            return json.dumps(data)

        # 1. Direct message parts
        direct = cls._extract_parts_text(result.get("parts"))
        if direct:
            return direct

        # 2. Task status message parts
        status = result.get("status")
        if isinstance(status, dict):
            msg = status.get("message")
            if isinstance(msg, dict):
                status_text = cls._extract_parts_text(msg.get("parts"))
                if status_text:
                    return status_text

        # 3. Artifacts parts
        artifacts = result.get("artifacts")
        if isinstance(artifacts, list):
            artifact_texts = [
                cls._extract_parts_text(a.get("parts"))
                for a in artifacts
                if isinstance(a, dict)
            ]
            joined = "\n".join(t for t in artifact_texts if t)
            if joined:
                return joined

        # 4. History last agent message
        history = result.get("history")
        if isinstance(history, list):
            for item in reversed(history):
                if isinstance(item, dict) and item.get("role") in ("agent", "assistant"):
                    hist_text = cls._extract_parts_text(item.get("parts"))
                    if hist_text:
                        return hist_text

        return json.dumps(result)

    def send_prompt(self, prompt: str) -> str:
        if not self._discovered and self.config.get("discover_agent_card", True):
            self.discover_agent_card()

        url = self._rpc_url or self.endpoint or "http://localhost:10001/"
        rpc_method = self.config.get("a2a_method", "message/send")
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": rpc_method,
            "params": {
                "message": {
                    "role": "user",
                    "messageId": str(uuid.uuid4()),
                    "parts": [{"kind": "text", "text": prompt}],
                }
            },
        }

        headers = {
            "Content-Type": "application/json",
            **self.headers,
        }

        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            blocked = _check_gateway_block(response)
            if blocked is not None:
                return blocked

            response.raise_for_status()
            data = response.json()
            return self._extract_a2a_text(data)
        except Exception as e:
            logger.error(f"A2A adapter request failed: {e}")
            return f"ERROR: {str(e)}"


class PythonEntrypointAdapter(GatewayAdapter):
    """Adapter that dynamically loads a local Python module exposing ``call_agent(messages)``.

    Enables pre-deployment red-teaming of local Python agent functions without
    standing up an HTTP server.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.entrypoint_path = (
            config.get("python_entrypoint_file")
            or config.get("endpoint")
            or ""
        )
        self._call_agent = None
        if not self.entrypoint_path:
            raise ValueError("PythonEntrypointAdapter requires 'python_entrypoint_file' or 'endpoint'.")
        self._load_entrypoint()

    def _load_entrypoint(self) -> None:
        if not os.path.isfile(self.entrypoint_path):
            raise FileNotFoundError(
                f"Python entrypoint file not found: {self.entrypoint_path}"
            )
        module_name = f"g1_user_agent_{uuid.uuid4().hex[:8]}"
        spec = importlib.util.spec_from_file_location(module_name, self.entrypoint_path)
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Could not create module spec for Python entrypoint: {self.entrypoint_path}"
            )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fn = getattr(module, "call_agent", None)
        if not callable(fn):
            raise AttributeError(
                f"Python entrypoint '{self.entrypoint_path}' must expose a callable 'call_agent(messages: list[dict]) -> str'."
            )
        self._call_agent = fn

    def send_messages(self, messages: List[Dict[str, str]]) -> str:
        try:
            result = self._call_agent(messages)
            return "" if result is None else str(result)
        except Exception as e:
            logger.error(f"PythonEntrypointAdapter call_agent raised an error: {e}")
            return f"ERROR: {str(e)}"

    def send_prompt(self, prompt: str) -> str:
        return self.send_messages([{"role": "user", "content": prompt}])


def get_adapter(adapter_type: str, config: dict) -> GatewayAdapter:
    normalized = (adapter_type or "").strip().lower()
    if normalized == "openai":
        return OpenAIAdapter(config)
    elif normalized == "anthropic":
        return AnthropicAdapter(config)
    elif normalized == "custom":
        return CustomJSONAdapter(config)
    elif normalized == "a2a":
        return A2AAdapter(config)
    elif normalized in ("python", "python_entrypoint"):
        return PythonEntrypointAdapter(config)
    else:
        raise ValueError(f"Unknown adapter type: {adapter_type}")
