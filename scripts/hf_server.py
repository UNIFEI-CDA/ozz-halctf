"""
Ozz — Resilient PyTorch/Transformers LLM Server (FastAPI)
OpenAI-compatible server with automatic CUDA sm_60 -> CPU FP32 fallback for high availability.
"""
import os
import sys
import torch
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from transformers import AutoModelForCausalLM, AutoTokenizer
import uvicorn

app = FastAPI(title="Ozz Resilient LLM Server")

MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-Coder-7B-Instruct")
CACHE_DIR = os.environ.get("HF_HOME", "/tmp/hf_cache")
PORT = int(os.environ.get("VLLM_PORT", os.environ.get("PORT", "8000")))

print(f"📥 Loading model: {MODEL_NAME}...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=CACHE_DIR, trust_remote_code=True)
current_device = "cuda" if torch.cuda.is_available() else "cpu"
dtype = torch.float16 if current_device == "cuda" else torch.float32

try:
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        cache_dir=CACHE_DIR,
        torch_dtype=dtype,
        device_map="auto" if current_device == "cuda" else "cpu",
        trust_remote_code=True,
        low_cpu_mem_usage=True
    )
    print(f"✅ Model loaded successfully on device: {current_device}!")
except Exception as e:
    print(f"⚠️ Warning loading on {current_device}: {e}. Falling back to CPU...")
    current_device = "cpu"
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        cache_dir=CACHE_DIR,
        torch_dtype=torch.float32,
        device_map="cpu",
        trust_remote_code=True,
        low_cpu_mem_usage=True
    )
    print("✅ Model loaded in CPU Fallback mode successfully!")

class ChatRequest(BaseModel):
    model: Optional[str] = MODEL_NAME
    messages: List[Dict[str, str]]
    max_tokens: int = 512
    temperature: float = 0.3

@app.get("/v1/models")
def get_models():
    return {"data": [{"id": MODEL_NAME}]}

@app.post("/v1/chat/completions")
def chat_completion(req: ChatRequest):
    global model, current_device
    prompt = tokenizer.apply_chat_template(req.messages, tokenize=False, add_generation_prompt=True)
    
    try:
        inputs = tokenizer(prompt, return_tensors="pt").to(current_device)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=req.max_tokens,
                temperature=req.temperature,
                do_sample=req.temperature > 0
            )
    except Exception as err:
        print(f"⚠️ Execution error on {current_device}: {err}. Performing CPU fallback...")
        current_device = "cpu"
        model = model.to("cpu").to(torch.float32)
        inputs = tokenizer(prompt, return_tensors="pt").to("cpu")
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=req.max_tokens,
                temperature=req.temperature,
                do_sample=req.temperature > 0
            )
    
    generated_ids = outputs[0][inputs.input_ids.shape[1]:]
    response_text = tokenizer.decode(generated_ids, skip_special_tokens=True)
    
    return {
        "choices": [{
            "message": {"role": "assistant", "content": response_text}
        }]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
