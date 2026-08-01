import requests
import json

# --- CONFIGURATION ---
# ตรวจสอบให้แน่ใจว่า URL และ Port ตรงกับ llama.cpp server ของคุณ
LLAMA_CPP_URL = "http://127.0.0.1:8080/completion"

# นี่คือ Prompt Template เต็มรูปแบบที่โมเดลของคุณถูกเทรนมา
PROMPT_TEMPLATE = (
    "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
    "You are mimicking a linux server. Respond with what the terminal would respond when a command given. I want you to only reply with the terminal outputs inside one unique code block and nothing else. Do not write any explanations. Do not type any commands unless I instruct you to do so.<|eot_id|>"
    "<|start_header_id|>user<|end_header_id|>\n\n{command}<|eot_id|>"
    "<|start_header_id|>assistant<|end_header_id|>\n"
)

def get_ai_response(command: str) -> str:
    """
    ฟังก์ชันนี้จะสร้าง Prompt เต็มรูปแบบและเรียกใช้ llama.cpp server
    """
    full_prompt = PROMPT_TEMPLATE.format(command=command)

    payload = {
        "prompt": full_prompt,
        "stream": False,
        "n_predict": 512,
        "temperature": 0.1,
        "stop": ["<|eot_id|>", "<|start_header_id|>", "user:", "human:"]
    }
    try:
        response = requests.post(LLAMA_CPP_URL, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return data.get("content", "Error: No content in response.").strip()
    except requests.exceptions.RequestException as e:
        return f"Error connecting to AI server: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

if __name__ == "__main__":
    print("--- Standalone AI Test Script ---")
    print("Enter a command to test, or type 'exit' to quit.")

    # รัน llama.cpp server ใน Terminal อีกหน้าต่างหนึ่งก่อน
    # ./build/bin/server -m models/honeypot_llm_beta.gguf -c 2048 --host 0.0.0.0 --port 8080
    
    while True:
        try:
            user_command = input("test-honeypot:~$ ")
            if user_command.lower() in ["exit", "quit"]:
                break
            
            print("\n...AI is thinking...")
            ai_output = get_ai_response(user_command)
            print("\n--- AI Response ---")
            print(ai_output)
            print("-------------------\n")

        except KeyboardInterrupt:
            print("\nExiting.")
            break

