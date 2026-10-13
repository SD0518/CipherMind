import requests
import json
import os
from dotenv import load_dotenv

class GeminiAgent:
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        self.api_key = os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found. Please set it in .env file or environment variable.")

        self.gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        self.conversation_history = []

    def send_message(self, user_input):
        # Google Gemini expects an array of 'contents' (multi-turn supported, here single-turn for clarity)
        self.conversation_history.append({"role": "user", "parts": [{"text": user_input}]})

        # Prepare Gemini request format
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": user_input}]}
            ]
        }

        headers = {"Content-Type": "application/json"}

        try:
            response = requests.post(self.gemini_url, json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            # Parse Gemini's response format
            if "candidates" in result and result["candidates"]:
                assistant_message = result["candidates"][0]["content"]["parts"][0]["text"]
                self.conversation_history.append({"role": "model", "parts": [{"text": assistant_message}]})
                return assistant_message
            else:
                return "No response from Gemini."
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Gemini API: {e}"
        except KeyError as e:
            return f"Error parsing Gemini response: {e}"
        except Exception as e:
            return f"Unexpected error: {e}"

    def run_conversation(self):
        print("Gemini Agent started! Type 'quit' to exit.")
        print("Using Gemini 1.5 Flash")
        print("=" * 50)

        while True:
            user_input = input("\nYou: ").strip()
            if user_input.lower() in ['quit', 'exit', 'bye']:
                print("\nAgent: Goodbye!")
                break
            if not user_input:
                continue
            print("\nAgent: ", end="", flush=True)
            response = self.send_message(user_input)
            print(response)

# Run the agent
if __name__ == "__main__":
    try:
        agent = GeminiAgent()
        agent.run_conversation()
    except ValueError as e:
        print(f"Setup Error: {e}")
        print("Get your free Gemini API key at: https://aistudio.google.com/app/apikey")
