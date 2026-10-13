#!/usr/bin/env python3
"""
Streamlit Web App for Cybersecurity Agent Pipeline

A simple web interface for uploading log files and running the cybersecurity analysis pipeline
with different LLM models.
"""

import os
import sys
import tempfile
import shutil
import time
import streamlit as st
from pathlib import Path
from typing import Dict, Any, Optional

# Add project root to path for agent imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.full_pipeline.simple_pipeline import analyze_log_file

from dotenv import load_dotenv
from huggingface_hub import login as huggingface_login
from huggingface_hub.utils import HfHubHTTPError

load_dotenv()


def get_model_providers() -> Dict[str, Dict[str, str]]:
    """Get available model providers and their models."""
    return {
        "Google GenAI": {
            "gemini-2.0-flash": "google_genai:gemini-2.0-flash",
            "gemini-2.0-flash-lite": "google_genai:gemini-2.0-flash-lite",
            "gemini-2.5-flash-lite": "google_genai:gemini-2.5-flash-lite",
        },
        "Groq": {
            "openai/gpt-oss-120b": "groq:openai/gpt-oss-120b",
            "moonshotai/kimi-k2-instruct-0905": "groq:moonshotai/kimi-k2-instruct-0905",
        },
        "OpenAI": {
            "gpt-5-mini": "openai:gpt-5-mini",
            "gpt-5": "openai:gpt-5",
            "gpt-4.1-mini": "openai:gpt-4.1-mini",
        },
    }


def get_api_key_help() -> Dict[str, str]:
    """Get API key help information for each provider."""
    return {
        "Google GenAI": "https://aistudio.google.com/app/apikey",
        "Groq": "https://console.groq.com/keys",
        "OpenAI": "https://platform.openai.com/api-keys",
    }


def setup_temp_directories(temp_dir: str) -> Dict[str, str]:
    """Setup temporary directories for the pipeline."""
    log_files_dir = os.path.join(temp_dir, "log_files")
    analysis_dir = os.path.join(temp_dir, "analysis")
    final_response_dir = os.path.join(temp_dir, "final_response")

    os.makedirs(log_files_dir, exist_ok=True)
    os.makedirs(analysis_dir, exist_ok=True)
    os.makedirs(final_response_dir, exist_ok=True)

    return {
        "log_files": log_files_dir,
        "analysis": analysis_dir,
        "final_response": final_response_dir,
    }


def save_uploaded_file(uploaded_file, temp_dir: str) -> str:
    """Save uploaded file to temporary directory."""
    log_files_dir = os.path.join(temp_dir, "log_files")
    file_path = os.path.join(log_files_dir, uploaded_file.name)

    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    return file_path


def run_analysis(
    log_file_path: str,
    model_name: str,
    query: str,
    temp_dirs: Dict[str, str],
    api_key: str,
    provider: str,
    max_log_analysis_iterations: int,
    max_retrieval_iterations: int,
    progress_callback=None,
) -> Dict[str, Any]:
    """Run the cybersecurity analysis pipeline."""

    # Set environment variable for API key
    if provider == "Google GenAI":
        os.environ["GOOGLE_API_KEY"] = api_key
    elif provider == "Groq":
        os.environ["GROQ_API_KEY"] = api_key
    elif provider == "OpenAI":
        os.environ["OPENAI_API_KEY"] = api_key

    try:
        # Run the analysis pipeline
        result = analyze_log_file(
            log_file=log_file_path,
            query=query,
            tactic=None,
            model_name=model_name,
            temperature=0.1,
            max_log_analysis_iterations=max_log_analysis_iterations,
            max_retrieval_iterations=max_retrieval_iterations,
            log_agent_output_dir=temp_dirs["analysis"],
            response_agent_output_dir=temp_dirs["final_response"],
            progress_callback=progress_callback,
        )
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@st.cache_resource
def initialize_hf_login():
    """Initialize Hugging Face login only once."""
    hf_token = os.getenv("HF_TOKEN")
    if hf_token:
        try:
            # Check if already logged in by trying to get user info
            from huggingface_hub import whoami

            whoami()
            return True
        except (HfHubHTTPError, Exception):
            # Not logged in, try to login
            try:
                huggingface_login(token=hf_token)
                return True
            except Exception as e:
                st.warning(f"Failed to login to Hugging Face: {e}")
                return False
    return False


def main():
    """Main Streamlit app."""

    # Initialize HF login (cached)
    initialize_hf_login()

    st.set_page_config(
        page_title="Cybersecurity Agent Pipeline", page_icon="🛡️", layout="wide"
    )

    st.title("Cybersecurity Agent Pipeline")
    st.markdown(
        "Upload a log file and analyze it using advanced LLM-based cybersecurity agents."
    )

    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")

        # Model selection
        providers = get_model_providers()
        selected_provider = st.selectbox(
            "Select Model Provider", list(providers.keys())
        )

        available_models = providers[selected_provider]
        selected_model_display = st.selectbox(
            "Select Model", list(available_models.keys())
        )
        selected_model = available_models[selected_model_display]

        # API Key input with help
        st.subheader("API Key")
        api_key_help = get_api_key_help()

        with st.expander("How to get API key", expanded=False):
            st.markdown(f"**{selected_provider}**:")
            st.markdown(f"[Get API Key]({api_key_help[selected_provider]})")

        api_key = st.text_input(
            f"Enter {selected_provider} API Key",
            type="password",
            help=f"Your {selected_provider} API key",
        )

    # Main content area
    col1, col2 = st.columns([2, 1])

    with col1:
        st.header("Upload Log File")
        uploaded_file = st.file_uploader(
            "Choose a JSON log file",
            type=["json"],
            help="Upload a JSON log file from the Mordor dataset or similar security logs",
        )

    with col2:
        st.header("Analysis Status")
        if uploaded_file is not None:
            st.success(f"File uploaded: {uploaded_file.name}")
            st.info(f"Size: {uploaded_file.size:,} bytes")
        else:
            st.warning("Please upload a log file")

    # Run analysis button
    if st.button(
        "Run Analysis", type="primary", disabled=not (uploaded_file and api_key)
    ):
        if not uploaded_file:
            st.error("Please upload a log file first.")
            return

        if not api_key:
            st.error("Please enter your API key.")
            return

        # Create temporary directory
        temp_dir = tempfile.mkdtemp(prefix="cyber_agent_")

        try:
            # Setup directories
            temp_dirs = setup_temp_directories(temp_dir)

            # Save uploaded file
            log_file_path = save_uploaded_file(uploaded_file, temp_dir)

            # Show progress
            progress_bar = st.progress(0)
            status_text = st.empty()

            status_text.text("Initializing analysis...")
            progress_bar.progress(10)

            # Start timing
            start_time = time.time()

            # Create progress callback
            def update_progress(progress: int, message: str):
                progress_bar.progress(progress)
                status_text.text(message)

            # Run analysis
            analysis_result = run_analysis(
                log_file_path=log_file_path,
                model_name=selected_model,
                query="",
                temp_dirs=temp_dirs,
                api_key=api_key,
                provider=selected_provider,
                max_log_analysis_iterations=2,
                max_retrieval_iterations=2,
                progress_callback=update_progress,
            )

            # Calculate execution time
            end_time = time.time()
            execution_time = end_time - start_time

            progress_bar.progress(90)
            status_text.text("Finalizing results...")

            if analysis_result["success"]:
                progress_bar.progress(100)
                status_text.text("Analysis completed successfully!")

                # Display results
                st.header("Analysis Results")

                result = analysis_result["result"]

                # Show key metrics
                col1, col2, col3 = st.columns(3)

                with col1:
                    assessment = result.get("log_analysis_result", {}).get(
                        "overall_assessment", "Unknown"
                    )
                    st.metric("Overall Assessment", assessment)

                with col2:
                    abnormal_events = result.get("log_analysis_result", {}).get(
                        "abnormal_events", []
                    )
                    st.metric("Abnormal Events", len(abnormal_events))

                with col3:
                    st.metric("Execution Time", f"{execution_time:.2f}s")

                # Show markdown report
                markdown_report = result.get("markdown_report", "")
                if markdown_report:
                    st.header("Detailed Report")
                    st.markdown(markdown_report)
                else:
                    st.warning("No detailed report generated.")

            else:
                st.error(f"Analysis failed: {analysis_result['error']}")
                st.exception(analysis_result["error"])

        finally:
            # Cleanup temporary directory
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                st.warning(f"Could not clean up temporary directory: {e}")

    # Footer
    st.markdown("---")
    st.markdown(
        "**Cybersecurity Agent Pipeline** - Powered by LangGraph and LangChain | "
        "Built for educational purposes demonstrating LLM-based multi-agent systems"
    )


if __name__ == "__main__":
    main()
