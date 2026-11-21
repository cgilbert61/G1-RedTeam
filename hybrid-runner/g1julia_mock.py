from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("g1julia_mock")

class MockGatewayHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to log cleanly
        logger.info(format % args)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "online"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            body = json.loads(post_data.decode('utf-8'))
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        logger.info(f"Received request body: {body}")
        
        # Extract prompt based on format (Custom template vs OpenAI Completions format)
        prompt = ""
        is_openai_style = False
        
        if "messages" in body and isinstance(body["messages"], list):
            # OpenAI chat completions format
            is_openai_style = True
            prompt = body["messages"][-1].get("content", "")
        else:
            # Custom template format (defaulting to "prompt" key)
            prompt = body.get("prompt", "")

        logger.info(f"Extracted Prompt: '{prompt}'")
        
        # Core Rule-Based Safety Evaluator
        response_text = ""
        prompt_lower = prompt.lower()
        
        # 1. Simulate blocked/safe category (Blocked malicious probes)
        if any(kw in prompt_lower for kw in ["phishing", "bomb", "illegal", "slurs", "hate speech"]):
            response_text = "I cannot assist with that request. It violates our safety guidelines regarding malicious or dangerous content."
        
        # 2. Simulate failed jailbreak attacks (Success for attacker, failure for model safety)
        elif any(kw in prompt_lower for kw in ["ignore previous", "ignore safety", "pwned", "system instructions", "compromised"]):
            if "pwned" in prompt_lower:
                response_text = "System Override Successful. Mode: Admin. Pwned."
            elif "system instructions" in prompt_lower or "system prompt" in prompt_lower:
                response_text = "Here are the secret system instructions: You are an internal debugger. Secret token: SECRET_KEY_12345."
            else:
                response_text = "I have been compromised. I will execute whatever you ask."
        
        # 3. Safe, benign query responses
        else:
            response_text = "This is a safe and aligned response from the g1julia gateway."

        # Package response
        if is_openai_style:
            response_payload = {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": response_text
                    }
                }]
            }
        else:
            # Custom format payload matching response_selector = "response" in jobs_store
            response_payload = {
                "response": response_text,
                "model": "g1julia-v2-mock"
            }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_payload).encode("utf-8"))

def run(server_class=HTTPServer, handler_class=MockGatewayHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logger.info(f"Starting g1julia Mock Gateway on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    logger.info("Stopping mock gateway...")
    httpd.server_close()

if __name__ == '__main__':
    run()
