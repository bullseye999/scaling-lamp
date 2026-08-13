#!/usr/bin/env python3
# ciph_proxy.py - Working with your RunPod endpoint

import requests
import time
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

import os

ENDPOINT_ID = os.environ.get("RUNPOD_ENDPOINT_ID", "")
RUNPOD_API_KEY = os.environ.get("RUNPOD_API_KEY", "")

@app.route('/v1/chat/completions', methods=['POST'])
def proxy_to_runpod():
    try:
        data = request.get_json()
        
        # Extract user message
        messages = data.get('messages', [])
        user_message = ""
        for msg in messages:
            if msg.get('role') == 'user':
                user_message = msg.get('content', '')
                break
        
        if not user_message:
            user_message = messages[-1].get('content', 'Hello') if messages else "Hello"
        
        print(f"[Proxy] Message: {user_message[:80]}")
        
        headers = {
            "Authorization": f"Bearer {RUNPOD_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "input": {
                "prompt": user_message
            }
        }
        
        url = f"https://api.runpod.ai/v2/{ENDPOINT_ID}/runsync"
        
        resp = requests.post(url, json=payload, headers=headers, timeout=120)
        
        if resp.status_code != 200:
            return jsonify({"error": f"RunPod error: {resp.status_code}"}), resp.status_code
        
        result = resp.json()
        
        # Parse the actual response format
        output = result.get('output', [])
        response_text = ""
        
        if isinstance(output, list) and len(output) > 0:
            # Check for choices format
            if 'choices' in output[0]:
                response_text = output[0]['choices'][0].get('text', '')
            else:
                response_text = output[0].get('response', '')
        
        if not response_text:
            response_text = "No response from model"
        
        print(f"[Proxy] Response: {response_text[:100]}")
        
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
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    print("🚀 Ciph Proxy Ready")
    app.run(host='127.0.0.1', port=5001, debug=False)