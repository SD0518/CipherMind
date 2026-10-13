import requests
import json
import os
from dotenv import load_dotenv

class GroqAgent:
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        
        self.api_key = os.getenv('GROQ_API_KEY')
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not found. Please set it in .env file or environment variable.")
        
        self.groq_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.1-8b-instant"  # Fast and free!
        self.conversation_history = []
        
    def send_message(self, user_input):
        # Add user message to conversation history
        self.conversation_history.append({
            "role": "user", 
            "content": user_input
        })
        
        # Prepare request payload
        payload = {
            "model": self.model,
            "messages": self.conversation_history,
            "temperature": 0.7,
            "max_tokens": 1000,
            "stream": False
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            # Send request to Groq
            response = requests.post(self.groq_url, json=payload, headers=headers)
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            assistant_message = result["choices"][0]["message"]["content"]
            
            # Add assistant response to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })
            
            return assistant_message
            
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Groq: {e}"
        except KeyError as e:
            return f"Error parsing response: {e}"
        except Exception as e:
            return f"Unexpected error: {e}"
    
    def run_conversation(self):
        print("Groq Agent started! Type 'quit' to exit.")
        print("Using Llama 3.1 8B")
        print("=" * 50)
        
        while True:
            # Get user input
            user_input = input("\nYou: ").strip()
            
            # Check for exit command
            if user_input.lower() in ['quit', 'exit', 'bye']:
                print("\nAgent: Goodbye!")
                break
            
            # Skip empty inputs
            if not user_input:
                continue
                
            # Get and display agent response
            print("\nAgent: ", end="", flush=True)
            response = self.send_message(user_input)
            print(response)

# Run the agent
if __name__ == "__main__":
    try:
        agent = GroqAgent()
        agent.run_conversation()
    except ValueError as e:
        print(f"Setup Error: {e}")
        print("Get your free API key at: https://console.groq.com/")