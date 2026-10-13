import streamlit as st
from groq_client import GroqClient

class ChatBotUI:
    def __init__(self):
        try:
            # Initialize the Groq client
            if 'groq_client' not in st.session_state:
                st.session_state.groq_client = GroqClient()
        except ValueError as e:
            st.error(str(e))
            st.stop()
    
    def display_chat_interface(self):
        st.title("Chat Assistant - Groq")
        
        # Display conversation history
        groq_client = st.session_state.groq_client
        conversation = groq_client.get_conversation_history()
        
        chat_container = st.container()
        with chat_container:
            for message in conversation:
                if message["role"] == "user":
                    st.markdown(f"**You:** {message['content']}")
                else:
                    st.markdown(f"**Assistant:** {message['content']}")
                st.markdown("---")
        
        # Input area
        with st.container():
            col1, col2, col3 = st.columns([4, 1, 1])
            
            with col1:
                user_input = st.text_input(
                    "Your message:",
                    key="user_input",
                    placeholder="Type your message here..."
                )
            
            with col2:
                st.markdown('<div style="margin-top: 28px;"></div>', unsafe_allow_html=True)
                send_button = st.button("Send", type="primary")
            
            with col3:
                st.markdown('<div style="margin-top: 28px;"></div>', unsafe_allow_html=True)
                clear_button = st.button("Clear", type="secondary")
        
        # Handle send button
        if send_button and user_input.strip():
            with st.spinner("Thinking..."):
                ai_response = groq_client.send_message(user_input)
            st.rerun()
        
        # Handle clear button
        if clear_button:
            groq_client.clear_conversation()
            st.rerun()
    
    def run_app(self):
        st.set_page_config(
            page_title="Chat Assistant - Groq",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        self.display_chat_interface()

def main():
    try:
        chatbot_ui = ChatBotUI()
        chatbot_ui.run_app()
    except Exception as e:
        st.error(f"Application Error: {e}")
        st.info("Make sure you have set your GROQ_API_KEY in the .env file")

if __name__ == "__main__":
    main()