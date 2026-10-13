import time
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from langchain_huggingface import HuggingFacePipeline
from langchain_core.messages import HumanMessage, SystemMessage


class HuggingFaceAgent:
    def __init__(self):
        self.model_id = "google/gemma-3-4b-it"  # You can change this to any HF model
        self.temperature = 0.3

        # Initialize the model and tokenizer
        print(f"Loading model {self.model_id}...")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch.float16,
            device_map="auto",
        )

        # Create a text generation pipeline
        pipe = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            max_new_tokens=512,
            temperature=self.temperature,
            top_p=0.9,
            repetition_penalty=1.1,
        )

        # Initialize the HuggingFace pipeline for LangChain
        self.chat = HuggingFacePipeline(pipeline=pipe)

        self.conversation_history = [
            SystemMessage(
                content="You are a helpful AI assistant. Be concise and informative."
            )
        ]

    def send_message(self, user_input):
        # Add user message to conversation history
        self.conversation_history.append(HumanMessage(content=user_input))

        try:
            # Send request to HuggingFace via Langchain
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
        print(
            f"HuggingFace Agent started with model {self.model_id}! Type 'quit' to exit."
        )
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
    agent = HuggingFaceAgent()
    agent.run_conversation()
