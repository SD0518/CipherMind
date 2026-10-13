from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
import time


class LangchainAgent:
    def __init__(self):
        self.model = "gemma3:4b"
        self.temperature = 0.3
        self.chat = ChatOllama(model=self.model, temperature=self.temperature)
        self.conversation_history = [
            SystemMessage(
                content="You are a helpful AI assistant. Be concise and informative."
            )
        ]

    def send_message(self, user_input):
        # Add user message to conversation history
        self.conversation_history.append(HumanMessage(content=user_input))

        try:
            # Send request to Ollama via Langchain
            start_time = time.time()
            resp = self.chat.invoke(self.conversation_history)
            end_time = time.time()

            # Calculate metrics
            time_taken = end_time - start_time
            words_per_second = (
                len(resp.content.split()) / time_taken if time_taken > 0 else 0
            )

            # Add assistant response to conversation history
            self.conversation_history.append(resp)

            # Print metrics
            print("\n" + "-" * 50)
            print(f"\nTime taken: {time_taken:.2f} seconds")
            print(f"Words per second: {words_per_second:.2f}")
            print("-" * 50)

            return resp.content

        except Exception as e:
            return f"Error: {e}"

    def run_conversation(self):
        print(f"Langchain Agent started with model {self.model}! Type 'quit' to exit.")
        print("=" * 50)

        while True:
            # Get user input
            user_input = input("\nYou: ").strip()

            # Check for exit command
            if user_input.lower() in ["quit", "exit", "bye"]:
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
    agent = LangchainAgent()
    agent.run_conversation()
