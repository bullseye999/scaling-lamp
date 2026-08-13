import os
import time
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

ENDPOINT_ID = os.environ.get("RUNPOD_ENDPOINT_ID", "")
RUNPOD_API_KEY = os.environ.get("RUNPOD_API_KEY", "")

def format_chat_messages(messages: list) -> str:
    """Format messages with Llama 3.1 chat template tags"""
    formatted = []
    for msg in messages:
        role = msg.get('role', 'user')
        content = msg.get('content', '')
        if role == 'system':
            formatted.append(f"<|start_header_id|>system<|end_header_id|>\n{content}<|eot_id|>")
        elif role == 'user':
            formatted.append(f"<|start_header_id|>user<|end_header_id|>\n{content}<|eot_id|>")
        elif role == 'assistant':
            formatted.append(f"<|start_header_id|>assistant<|end_header_id|>\n{content}<|eot_id|>")
    
    formatted.append("<|start_header_id|>assistant<|end_header_id|>\n")
    return "\n".join(formatted)

def call_runpod_with_retry(url: str, payload: dict, headers: dict, max_retries: int = 3) -> dict:
    """Call RunPod endpoint with retry and backoff"""
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=120)
            if resp.status_code == 200:
                return resp.json()
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

    data = request.get_json() or {}
    messages = data.get('messages', [])
    
    full_prompt = format_chat_messages(messages)
    
    headers = {
        "Authorization": f"Bearer {RUNPOD_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "input": {
            "prompt": full_prompt,
            "temperature": data.get('temperature', 0.3),
            "max_tokens": data.get('max_tokens', 600)
        }
    }
    url = f"https://api.runpod.ai/v2/{ENDPOINT_ID}/runsync"
    
    try:
        result = call_runpod_with_retry(url, payload, headers)
        
        output = result.get('output', [])
        response_text = ""
        if isinstance(output, list) and len(output) > 0:
            first = output[0]
            if isinstance(first, dict):
                if 'choices' in first and len(first['choices']) > 0:
                    response_text = first['choices'][0].get('text', '')
                elif 'response' in first:
                    response_text = first['response']
            elif isinstance(first, str):
                response_text = first
        
        if not response_text:
            response_text = "No response from model"
        
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
    return jsonify({"status": "ok", "endpoint": ENDPOINT_ID})

if __name__ == '__main__':
    print("🚀 Ciph Proxy with Llama 3.1 Template & Retry Support")
    app.run(host='127.0.0.1', port=5001, debug=False)