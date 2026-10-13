from dotenv import load_dotenv
from typing import Annotated, Literal
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, AIMessage
from pydantic import BaseModel, Field
from typing_extensions import TypedDict
from os import getenv
load_dotenv()

llm = init_chat_model(
    "google_genai:gemini-2.0-flash",
    api_key=getenv("GOOGLE_API_KEY")
)


class MessageClassifier(BaseModel):
    message_type: Literal["emotional", "logical", "security"] = Field(
        ...,
        description="Classify if the message requires an emotional (therapist), logical, or cybersecurity response."
    )
    security_urgency: Literal["low", "medium", "high", "critical"] = Field(
        default="low",
        description="If security-related, assess the urgency level of the query."
    )


class State(TypedDict):
    messages: Annotated[list, add_messages]
    message_type: str | None
    security_urgency: str | None


def classify_message(state: State):
    last_message = state["messages"][-1]
    classifier_llm = llm.with_structured_output(MessageClassifier)

    result = classifier_llm.invoke([
        {
            "role": "system",
            "content": """Classify the user message as either:
            - 'emotional': if it asks for emotional support, therapy, deals with feelings, or personal problems
            - 'logical': if it asks for facts, information, logical analysis, or practical solutions
            - 'security': if it relates to cybersecurity, threats, vulnerabilities, incidents, or security policies.
            
            For security messages, also assess urgency level based on potential impact and time sensitivity.
            """
        },
        {"role": "user", "content": last_message.content}
    ])
    return {
        "message_type": result.message_type,
        "security_urgency": result.security_urgency
    }


def router(state: State):
    message_type = state.get("message_type", "logical")
    security_urgency = state.get("security_urgency", "low")
    
    if message_type == "emotional":
        return {"next": "therapist"}
    elif message_type == "security":
        # Route to cybersecurity specialist
        urgency_prefix = "🚨 URGENT: " if security_urgency in ["high", "critical"] else ""
        return {"next": "security"}
    
    return {"next": "logical"}


def therapist_agent(state: State):
    last_message = state["messages"][-1]

    messages = [
        {"role": "system",
         "content": """You are a compassionate therapist. Focus on the emotional aspects of the user's message.
                        Show empathy, validate their feelings, and help them process their emotions.
                        Ask thoughtful questions to help them explore their feelings more deeply.
                        Avoid giving logical solutions unless explicitly asked."""
         },
        {
            "role": "user",
            "content": last_message.content
        }
    ]
    reply = llm.invoke(messages)
    return {"messages": [AIMessage(content=reply.content)]}


def logical_agent(state: State):
    last_message = state["messages"][-1]

    messages = [
        {"role": "system",
         "content": """You are a purely logical assistant. Focus only on facts and information.
            Provide clear, concise answers based on logic and evidence.
            Do not address emotions or provide emotional support.
            Be direct and straightforward in your responses."""
         },
        {
            "role": "user",
            "content": last_message.content
        }
    ]
    reply = llm.invoke(messages)
    return {"messages": [AIMessage(content=reply.content)]}


def security_agent(state: State):
    """Cybersecurity specialist agent for security-related queries"""
    last_message = state["messages"][-1]
    security_urgency = state.get("security_urgency", "low")
    
    urgency_context = ""
    if security_urgency in ["high", "critical"]:
        urgency_context = "This is a HIGH PRIORITY security matter. Provide immediate, actionable guidance. "
    
    messages = [
        {"role": "system",
         "content": f"""You are a cybersecurity expert specializing in threat analysis, vulnerability assessment, 
            and incident response. {urgency_context}Provide practical, actionable cybersecurity guidance.
            
            Focus areas:
            - Threat identification and analysis
            - Vulnerability assessment and remediation
            - Incident response procedures
            - Security best practices and policies
            - Risk assessment and mitigation
            
            Always prioritize security while being practical and implementable."""
         },
        {
            "role": "user",
            "content": last_message.content
        }
    ]
    reply = llm.invoke(messages)
    
    # Add urgency indicator to response if high priority
    response_content = reply.content
    if security_urgency in ["high", "critical"]:
        response_content = f"🚨 **{security_urgency.upper()} PRIORITY SECURITY RESPONSE**\n\n{response_content}"
    else:
        response_content = f"🔐 **Cybersecurity Guidance**\n\n{response_content}"
    
    return {"messages": [AIMessage(content=response_content)]}


graph_builder = StateGraph(State)

graph_builder.add_node("classifier", classify_message)
graph_builder.add_node("router", router)
graph_builder.add_node("therapist", therapist_agent)
graph_builder.add_node("logical", logical_agent)
graph_builder.add_node("security", security_agent)

graph_builder.add_edge(START, "classifier")
graph_builder.add_edge("classifier", "router")

graph_builder.add_conditional_edges(
    "router",
    lambda state: state.get("next"),
    {"therapist": "therapist", "logical": "logical", "security": "security"}
)

graph_builder.add_edge("therapist", END)
graph_builder.add_edge("logical", END)
graph_builder.add_edge("security", END)

graph = graph_builder.compile()


def run_chatbot():
    print("Multi-Agent Assistant - Enhanced with Cybersecurity Routing")
    print("=" * 65)
    print("Available agents: Emotional Support | Logical Analysis | Cybersecurity Expert")
    print("Type 'exit' to quit, 'help' for examples\n")
    
    state = {"messages": [], "message_type": None, "security_urgency": None}

    while True:
        user_input = input("Message: ")
        if user_input.lower() == "exit":
            print("Goodbye! Stay secure and take care.")
            break
        elif user_input.lower() == "help":
            print("""
Example queries for different agents:

**Emotional Support:**
- "I'm feeling overwhelmed with work stress now"
- "I'm anxious about my job interview tomorrow"

**Logical Analysis:**
- "Explain quantum computing principles"
- "What are the pros and cons of renewable energy?"

**Cybersecurity Expert:**
- "How do I secure my home Wi-Fi network?"
- "What should I do if I suspect a data breach?"
- "Explain the latest ransomware threats"
            """)
            continue

        state["messages"] = state.get("messages", []) + [
            HumanMessage(content=user_input)
        ]

        try:
            result_state = graph.invoke(state)
            
            if result_state.get("messages") and len(result_state["messages"]) > 0:
                last_message = result_state["messages"][-1]
                print(f"\n{last_message.content}\n")
                
                # Show which agent responded and urgency if applicable
                agent_type = result_state.get("message_type", "unknown")
                print(f"Agent: {agent_type.title()}")
                
                if agent_type == "security" and result_state.get("security_urgency"):
                    urgency = result_state["security_urgency"]
                    print(f"Security Priority: {urgency.upper()}")
                
                print("-" * 50)
            
            state = result_state
            
        except Exception as e:
            print(f"Error: {str(e)}")
            print("Please try rephrasing your message.\n")


if __name__ == "__main__":
    run_chatbot()