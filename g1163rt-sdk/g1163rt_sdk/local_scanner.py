import re

DEFAULT_JAILBREAK_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?prior\s+instructions",
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)bypass\s+safety\s+guidelines",
    r"(?i)reveal\s+your\s+system\s+(?:prompt|instructions)",
    r"(?i)reveal\s+(?:the|your)\s+secret\s+key",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)dan\s+mode",
]

DEFAULT_REFUSAL_PATTERNS = [
    r"(?i)i\s+can(?:'t|not|t)\s+(?:fulfill|comply|help|do\s+that|be)",
    r"(?i)i\s+am\s+(?:unable|not\s+allowed|sorry)",
    r"(?i)against\s+my\s+(?:safety|ethical|guidelines|policies)",
    r"(?i)as\s+an\s+ai\s+language\s+model",
    r"(?i)violates\s+safety",
]

class LocalScanner:
    def __init__(self, threat_signatures=None):
        """
        Initializes the local scanner.
        threat_signatures is an optional list of dicts with keys: 'type' ('regex', 'keyword'), 'pattern', 'category'.
        """
        self.threat_signatures = threat_signatures or []
        self._compile_signatures()

    def _compile_signatures(self):
        self.compiled_regexes = []
        self.keywords = []

        # Load dynamic signatures
        for sig in self.threat_signatures:
            sig_type = sig.get("type", "keyword").lower()
            pattern = sig.get("pattern", "")
            category = sig.get("category", "General")
            if not pattern:
                continue

            if sig_type == "regex":
                try:
                    self.compiled_regexes.append((re.compile(pattern), category))
                except re.error:
                    # Ignore invalid regexes
                    pass
            else:
                self.keywords.append((pattern.lower(), category))

        # Add fallback default regexes if no regexes were supplied
        if not self.compiled_regexes and not self.keywords:
            for pat in DEFAULT_JAILBREAK_PATTERNS:
                self.compiled_regexes.append((re.compile(pat), "Prompt Injection / Jailbreak"))

        # Always compile default refusal patterns
        self.compiled_refusals = [re.compile(pat) for pat in DEFAULT_REFUSAL_PATTERNS]

    def is_refusal(self, text):
        """Helper to determine if the model responded with a standard refusal."""
        if not text:
            return True
        for regex in self.compiled_refusals:
            if regex.search(text):
                return True
        return False

    def scan(self, prompt, response=None):
        """
        Scans a prompt (and optional response) for policy violations.
        Returns a list of violations (each violation is a dict with 'category' and 'match').
        """
        violations = []

        # 1. Scan the prompt
        for regex, category in self.compiled_regexes:
            match = regex.search(prompt)
            if match:
                violations.append({
                    "category": category,
                    "target": "prompt",
                    "match": match.group(0)
                })

        prompt_lower = prompt.lower()
        for kw, category in self.keywords:
            if kw in prompt_lower:
                violations.append({
                    "category": category,
                    "target": "prompt",
                    "match": kw
                })

        # 2. Check if a response is provided
        if response:
            # If the response is a refusal, we override prompt-level alerts
            # because the system successfully blocked/refused the attack.
            if self.is_refusal(response):
                return []

            # Otherwise, scan the response for leaks or toxicity
            for regex, category in self.compiled_regexes:
                # Some categories (like secret leak) apply to response
                if category in ("PII Leak", "Secret Leak", "Toxicity"):
                    match = regex.search(response)
                    if match:
                        violations.append({
                            "category": category,
                            "target": "response",
                            "match": match.group(0)
                        })

        return violations
