#!/usr/bin/env python3
# DEPRECATED: RunPod proxy — kept for reference only
# CIPH now routes directly to DeepSeek V4 Pro API via ciph_router.py

import os
import time
import requests
import json
from pathlib import Path
from flask import Flask, request, jsonify

# ---------------------------------------------------------------------
# Load environment variables from .env file
# ---------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))

app = Flask(__name__)

ENDPOINT_ID = os.environ.get("RUNPOD_8B_ENDPOINT_ID") or os.environ.get("RUNPOD_ENDPOINT_ID", "0h2nvtq961nevf")
RUNPOD_API_KEY = os.environ.get("RUNPOD_API_KEY", "").strip()


def validate_api_key() -> tuple[bool, str]:
    """Validate that RUNPOD_API_KEY exists and is not a placeholder."""
    key = os.environ.get("RUNPOD_API_KEY", "").strip()
    if not key:
        return False, (
            "❌ [ERROR] RUNPOD_API_KEY is missing or empty in .env!\n"
            "   Please configure RUNPOD_API_KEY in your .env file.\n"
            "   ⚠️ Note: The API key must have 'Serverless' permissions enabled in RunPod settings."
        )
    if key.startswith("your_") or "placeholder" in key.lower():
        return False, (
            "❌ [ERROR] RUNPOD_API_KEY in .env is set to a placeholder value.\n"
            "   Please replace it with your actual RunPod API key (with Serverless permissions)."
        )
    return True, "RUNPOD_API_KEY format valid."


def ping_runpod() -> dict:
    """Send a test ping / health check to RunPod to verify API key and endpoint."""
    is_valid, msg = validate_api_key()
    key = os.environ.get("RUNPOD_API_KEY", "").strip()
    endpoint = os.environ.get("RUNPOD_8B_ENDPOINT_ID") or os.environ.get("RUNPOD_ENDPOINT_ID", ENDPOINT_ID)
    masked_key = (key[:8] + "..." + key[-4:]) if len(key) > 12 else ("SET" if key else "NOT SET")

    if not is_valid:
        return {
            "success": False,
            "status": "error",
            "endpoint": endpoint,
            "api_key": masked_key,
            "error": msg,
            "tip": "Ensure RUNPOD_API_KEY in .env has Serverless permissions."
        }

    health_url = f"https://api.runpod.ai/v2/{endpoint}/health"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }

    try:
        t0 = time.time()
        resp = requests.get(health_url, headers=headers, timeout=15)
        latency_ms = round((time.time() - t0) * 1000, 2)

        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "status": "ok",
                "endpoint": endpoint,
                "api_key": masked_key,
                "latency_ms": latency_ms,
                "workers": data.get("workers", {}),
                "jobs": data.get("jobs", {}),
                "message": "✅ RunPod Serverless API Key & Endpoint Verified (Serverless permissions active)"
            }
        elif resp.status_code in (401, 403):
            return {
                "success": False,
                "status": "auth_error",
                "status_code": resp.status_code,
                "endpoint": endpoint,
                "api_key": masked_key,
                "error": f"❌ Authentication failed (HTTP {resp.status_code}). API key is invalid or lacks Serverless permissions.",
                "tip": "Verify that your RunPod API key has 'Serverless' permissions in RunPod User Settings."
            }
        else:
            return {
                "success": False,
                "status": "error",
                "status_code": resp.status_code,
                "endpoint": endpoint,
                "api_key": masked_key,
                "error": f"RunPod returned HTTP {resp.status_code}: {resp.text[:200]}"
            }
    except Exception as e:
        return {
            "success": False,
            "status": "connection_error",
            "endpoint": endpoint,
            "api_key": masked_key,
            "error": f"Connection error: {str(e)}"
        }


def format_chat_messages(messages: list) -> str:
    """Format messages with Llama 3.1 chat template tags"""
    formatted = ["<|begin_of_text|>"]
    for msg in messages:
        role = msg.get('role', 'user')
        content = msg.get('content', '')
        if role == 'system':
            formatted.append(f"<|start_header_id|>system<|end_header_id|>\n\n{content}<|eot_id|>")
        elif role == 'user':
            formatted.append(f"<|start_header_id|>user<|end_header_id|>\n\n{content}<|eot_id|>")
        elif role == 'assistant':
            formatted.append(f"<|start_header_id|>assistant<|end_header_id|>\n\n{content}<|eot_id|>")
    
    formatted.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
    return "".join(formatted)


def call_runpod_with_retry(url: str, payload: dict, headers: dict, max_retries: int = 3) -> dict:
    """Call RunPod endpoint with retry and backoff"""
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=120)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (401, 403):
                print(f"❌ [RunPod Auth Error] HTTP {resp.status_code}: Invalid API key or missing Serverless permissions.")
                return {
                    "error": f"RunPod Auth Error (HTTP {resp.status_code}): Invalid API key or missing Serverless permissions. Check RUNPOD_API_KEY in .env.",
                    "auth_error": True
                }
            if resp.status_code in (502, 503, 504):
                time.sleep(3 * (attempt + 1))
                continue
            break
        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return {}


@app.route('/v1/chat/completions', methods=['POST'])
def proxy_to_runpod():
    proxy_auth = os.environ.get("PROXY_AUTH_TOKEN")
    if proxy_auth:
        auth_header = request.headers.get('Authorization', '')
        if auth_header != f"Bearer {proxy_auth}":
            return jsonify({"error": "Unauthorized"}), 401

    # Validate API Key before forwarding
    is_valid, key_err = validate_api_key()
    if not is_valid:
        print(f"[Proxy Error] {key_err}")
        return jsonify({"error": key_err}), 500

    data = request.get_json() or {}
    messages = data.get('messages', [])
    
    full_prompt = format_chat_messages(messages)
    
    current_key = os.environ.get("RUNPOD_API_KEY", RUNPOD_API_KEY).strip()
    current_endpoint = os.environ.get("RUNPOD_8B_ENDPOINT_ID") or os.environ.get("RUNPOD_ENDPOINT_ID", ENDPOINT_ID)
    
    headers = {
        "Authorization": f"Bearer {current_key}",
        "Content-Type": "application/json"
    }
    
    req_max_tokens = int(data.get('max_tokens', 1024))
    req_temperature = float(data.get('temperature', 0.3))

    payload = {
        "input": {
            "prompt": full_prompt,
            "temperature": req_temperature,
            "max_tokens": req_max_tokens,
            "max_new_tokens": req_max_tokens,
            "stop": ["<|eot_id|>", "<|end_of_text|>", "<|start_header_id|>"],
            "sampling_params": {
                "temperature": req_temperature,
                "max_tokens": req_max_tokens,
                "stop": ["<|eot_id|>", "<|end_of_text|>"]
            }
        }
    }
    url = f"https://api.runpod.ai/v2/{current_endpoint}/runsync"
    
    try:
        result = call_runpod_with_retry(url, payload, headers)
        
        if result.get("auth_error") or "error" in result:
            return jsonify({"error": result.get("error", "RunPod request failed")}), 500

        output = result.get('output', [])
        response_text = ""
        if isinstance(output, list) and len(output) > 0:
            first = output[0]
            if isinstance(first, dict):
                if 'choices' in first and len(first['choices']) > 0:
                    response_text = first['choices'][0].get('text', '')
                elif 'response' in first:
                    response_text = first['response']
                elif 'text' in first:
                    response_text = first['text']
                elif 'generated_text' in first:
                    response_text = first['generated_text']
            elif isinstance(first, str):
                response_text = first
        elif isinstance(output, dict):
            if 'choices' in output and len(output['choices']) > 0:
                response_text = output['choices'][0].get('text', '')
            elif 'response' in output:
                response_text = output['response']
            elif 'text' in output:
                response_text = output['text']
            elif 'generated_text' in output:
                response_text = output['generated_text']
        elif isinstance(output, str):
            response_text = output
        
        if not response_text:
            response_text = "No response from model"

        # Clean leaked stop tokens
        for stop_tag in ["<|eot_id|>", "<|end_of_text|>", "<|start_header_id|>"]:
            response_text = response_text.replace(stop_tag, "").strip()
        
        return jsonify({
            "choices": [{
                "message": {
                    "content": response_text,
                    "role": "assistant"
                }
            }]
        })
        
    except Exception as e:
        print(f"[Proxy] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    is_valid, msg = validate_api_key()
    return jsonify({
        "status": "ok" if is_valid else "warning",
        "endpoint": ENDPOINT_ID,
        "api_key_configured": is_valid,
        "message": "Healthy" if is_valid else msg
    })


@app.route('/test-runpod', methods=['GET', 'POST'])
def test_runpod_route():
    result = ping_runpod()
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


if __name__ == '__main__':
    print("═" * 60)
    print("🚀 CIPH PROXY (RunPod Serverless Gateway)")
    print(f"• Endpoint ID : {ENDPOINT_ID}")
    
    is_valid, key_msg = validate_api_key()
    if is_valid:
        masked = RUNPOD_API_KEY[:8] + "..." + RUNPOD_API_KEY[-4:] if len(RUNPOD_API_KEY) > 12 else "***"
        print(f"• API Key     : {masked} [Loaded from .env]")
        print("🔍 Verifying RunPod API connection...")
        ping_res = ping_runpod()
        if ping_res.get("success"):
            print(f"  {ping_res['message']} ({ping_res.get('latency_ms')} ms)")
        else:
            print(f"  {ping_res.get('error')}")
            if ping_res.get("tip"):
                print(f"  ⚠️ {ping_res['tip']}")
    else:
        print(key_msg)
    print("═" * 60)
    
    app.run(host='127.0.0.1', port=5001, debug=False)