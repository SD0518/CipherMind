import os
import time
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain.schema import HumanMessage, AIMessage, SystemMessage

class SimpleAgent:
    def __init__(self, name, role, personality, api_key):
        self.name = name
        self.role = role
        self.personality = personality
        
        # Initialize Groq LLM
        self.llm = ChatGroq(
            groq_api_key=api_key,
            model="llama-3.1-8b-instant",
            temperature=0.7
        )
        
        # System prompt that defines the agent's behavior
        self.system_prompt = f"""
You are {self.name}, a {self.role}.

Your personality: {self.personality}

Important instructions:
- Always stay in character as {self.name}
- Keep responses conversational and under 100 words
- Show your personality in your responses
- When responding to another agent, address them by name
- End with a question or comment to keep the conversation flowing
"""

    def respond(self, message, sender_name=None):
        """Generate a response to a message"""
        if sender_name:
            formatted_message = f"Message from {sender_name}: {message}"
        else:
            formatted_message = message
        
        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=formatted_message)
        ]
        
        response = self.llm.invoke(messages)
        return response.content

class TwoAgentSystem:
    def __init__(self, api_key):
        # Create two agents with different personalities
        self.agent1 = SimpleAgent(
            name="Alice",
            role="Creative Writer",
            personality="Enthusiastic, imaginative, loves storytelling and asking creative questions. Uses lots of exclamation points!",
            api_key=api_key
        )
        
        self.agent2 = SimpleAgent(
            name="Bob", 
            role="Logical Analyst",
            personality="Thoughtful, analytical, prefers facts and structured thinking. Asks clarifying questions and likes to break things down step by step.",
            api_key=api_key
        )
        
        self.conversation_history = []
    
    def start_conversation(self, initial_topic):
        """Start a conversation between the two agents"""
        print("Two-Agent Communication System Started!")
        print(f"Topic: {initial_topic}")
        print("=" * 60)
        print("Type 'quit' at any time to exit the conversation.")
        
        # Agent 1 starts the conversation
        current_speaker = self.agent1
        other_agent = self.agent2
        current_message = initial_topic
        
        # Run conversation until user quits
        turn = 0
        while True:
            print(f"\n{current_speaker.name} ({current_speaker.role}):")
            print("-" * 40)
            
            if turn == 0:
                # First message is the topic
                response = current_speaker.respond(current_message)
            else:
                # Subsequent messages reference the previous response
                response = current_speaker.respond(current_message, other_agent.name)
            
            print(response)
            
            # Store in conversation history
            self.conversation_history.append({
                "turn": turn + 1,
                "speaker": current_speaker.name,
                "message": response
            })
            
            # Prompt user to continue, chat, or quit
            user_input = input("Press Enter to continue, type a message to chat, or type 'quit' to exit: ")
            if user_input.lower() == 'quit':
                break
            elif user_input.strip() != "":
                # User wants to chat - send their message to current agent
                print(f"\nYou:")
                print("-" * 40)
                print(user_input)
                
                # Get response from the current agent
                agent_response = current_speaker.respond(user_input, "User")
                
                print(f"\n{current_speaker.name} ({current_speaker.role}):")
                print("-" * 40)
                print(agent_response)
                
                # Store in conversation history
                self.conversation_history.append({
                    "turn": turn + 1.5,  # Use half-turn to indicate user interaction
                    "speaker": "User",
                    "message": user_input
                })
                self.conversation_history.append({
                    "turn": turn + 1.75,  # Use half-turn to indicate response to user
                    "speaker": current_speaker.name,
                    "message": agent_response
                })
                
                # Continue with normal flow after user interaction
                user_continue = input("Press Enter to continue with the regular conversation or type 'quit' to exit: ")
                if user_continue.lower() == 'quit':
                    break
                
                # Continue with the response to the other agent
                current_message = response
            
            # Switch speakers for next turn
            current_speaker, other_agent = other_agent, current_speaker
            current_message = response
            turn += 1
        
        print("\nConversation Complete!")
        print("=" * 60)
    
    def show_summary(self):
        """Show a summary of the conversation"""
        print("\nConversation Summary:")
        print("-" * 30)
        for entry in self.conversation_history:
            print(f"Turn {entry['turn']} - {entry['speaker']}: {entry['message'][:50]}...")

def main():
    # Load environment variables
    load_dotenv()
    
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        api_key = input("Enter your Groq API key: ").strip()
    
    if not api_key:
        print("No API key provided!")
        return
    
    # Create the two-agent system
    system = TwoAgentSystem(api_key)
    
    print("Welcome to the Multi-Agent Communication System!")
    print("\nYou'll watch Alice (Creative Writer) and Bob (Logical Analyst) discuss a topic.")
    print("Alice is enthusiastic and creative, Bob is analytical and structured.\n")
    
    # Get topic from user
    topic = input("What topic should they discuss? (or press Enter for default): ").strip()
    if not topic:
        topic = "The future of artificial intelligence and its impact on creativity"
    
    # Start the conversation
    system.start_conversation(topic)
    
    # Show summary
    system.show_summary()

if __name__ == "__main__":
    main()