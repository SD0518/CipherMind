import os
import requests
from dotenv import load_dotenv

class GroqClient:
    def __init__(self):
        load_dotenv()
        
        self.api_key = os.getenv('GROQ_API_KEY')
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not found. Please set it in .env file or environment variable.")
        
        self.model_name = "llama-3.1-8b-instant"
        self.conversation_history = []
    
    def send_message(self, user_message):
        # Send message to Groq and get response
        try:
            # Add user message to history
            self.conversation_history.append({"role": "user", "content": user_message})
            
            # Prepare messages for API
            messages = [{"role": "system", "content": "You are a helpful AI assistant."}]
            messages.extend(self.conversation_history)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": self.model_name,
                "messages": messages,
                "temperature": 0.8,
                "max_tokens": 800
            }
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result['choices'][0]['message']['content']
                
                # Add AI response to history
                self.conversation_history.append({"role": "assistant", "content": ai_response})
                
                return ai_response
            else:
                raise Exception(f"API Error: {response.text}")
                
        except Exception as e:
            if "rate limit" in str(e).lower():
                return "Rate limit exceeded. Please try again later."
            elif "invalid api key" in str(e).lower():
                return "Invalid API key. Please check your GROQ_API_KEY."
            else:
                return f"Error: {str(e)}"
    
    def get_conversation_history(self):
        # Get the conversation history
        return self.conversation_history
    
    def clear_conversation(self):
        # Clear the conversation history
        self.conversation_history = []