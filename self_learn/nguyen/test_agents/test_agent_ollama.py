import requests
import json
import time

class OptimizedBasicAgent:
    def __init__(self):
        self.ollama_url = "http://localhost:11434/api/chat"
        self.model = "gemma3:4b"
        self.conversation_history = []
        
        # Create a persistent session for connection reuse
        self.session = requests.Session()
        
        # Add system message for better performance
        self.conversation_history.append({
            "role": "system",
            "content": "You are a helpful AI assistant. Be concise and informative."
        })
        
    def send_message(self, user_input):
        # Add user message to conversation history
        self.conversation_history.append({
            "role": "user", 
            "content": user_input
        })
        
        # Prepare request payload with optimizations
        payload = {
            "model": self.model,
            "messages": self.conversation_history,
            "stream": False,
            "options": {
                "temperature": 0.3,  # Lower temperature for faster responses
                "top_p": 0.9,
                "top_k": 40
            }
        }
        
        try:
            # Start timing the response
            start_time = time.time()
            
            # Send request using persistent session
            response = self.session.post(self.ollama_url, json=payload)
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            assistant_message = result["message"]["content"]
            
            # End timing and calculate metrics
            end_time = time.time()
            time_taken = end_time - start_time
            word_count = len(assistant_message.split())
            words_per_second = word_count / time_taken if time_taken > 0 else 0
            
            # Add assistant response to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })
            
            return {
                "content": assistant_message,
                "time_taken": time_taken,
                "words_per_second": words_per_second
            }
            
        except requests.exceptions.RequestException as e:
            return {
                "content": f"Error connecting to Ollama: {e}",
                "time_taken": 0,
                "words_per_second": 0
            }
        except KeyError as e:
            return {
                "content": f"Error parsing response: {e}",
                "time_taken": 0,
                "words_per_second": 0
            }
    
    def run_conversation(self):
        print("Optimized Basic Agent started! Type 'quit' to exit.")
        print("=" * 50)
        
        while True:
            # Get user input
            user_input = input("\nYou: ").strip()
            
            # Check for exit command
            if user_input.lower() in ['quit', 'exit', 'bye']:
                print("\nAgent: Goodbye!")
                self.session.close()  # Clean up session
                break
            
            # Skip empty inputs
            if not user_input:
                continue
                
            # Get and display agent response
            print("\nAgent: ", end="", flush=True)
            response_data = self.send_message(user_input)
            
            print(response_data["content"])
            print(f"Time taken: {response_data['time_taken']:.2f} seconds")
            print(f"Words per second: {response_data['words_per_second']:.2f}")

# Run the agent
if __name__ == "__main__":
    agent = OptimizedBasicAgent()
    agent.run_conversation()