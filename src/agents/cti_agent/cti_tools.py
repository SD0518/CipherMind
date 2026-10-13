import json

import requests
from langchain_tavily import TavilySearch
from langchain.chat_models import init_chat_model
from langsmith import traceable

from src.agents.cti_agent.config import (
    IOC_EXTRACTION_PROMPT,
    THREAT_ACTOR_PROMPT,
    MITRE_EXTRACTION_PROMPT,
)


class CTITools:
    """Collection of specialized tools for CTI analysis."""

    def __init__(self, llm, search: TavilySearch):
        """
        Initialize CTI tools.

        Args:
            llm: Language model for analysis
            search: Search tool for finding CTI reports
        """
        self.llm = llm
        self.search = search

    @traceable(name="cti_search_reports")
    def search_cti_reports(self, query: str) -> str:
        """
        Specialized search for CTI reports with enhanced queries.

        Args:
            query: Search query for CTI reports

        Returns:
            JSON string with search results
        """
        try:
            # Enhance query with CTI-specific terms if not already present
            enhanced_query = query
            if "report" not in query.lower() and "analysis" not in query.lower():
                enhanced_query = f"{query} threat intelligence report"

            results = self.search.invoke(enhanced_query)

            # Format results for better parsing
            formatted_results = {
                "query": enhanced_query,
                "found": len(results.get("results", [])),
                "reports": [],
            }

            for idx, result in enumerate(results.get("results", [])[:5]):
                formatted_results["reports"].append(
                    {
                        "index": idx + 1,
                        "title": result.get("title", "No title"),
                        "url": result.get("url", ""),
                        "snippet": result.get("content", "")[:500],
                        "score": result.get("score", 0),
                    }
                )

            return json.dumps(formatted_results, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e), "query": query})

    @traceable(name="cti_extract_url_from_search")
    def extract_url_from_search(self, search_result: str, index: int = 0) -> str:
        """
        Extract a specific URL from search results JSON.

        Args:
            search_result: JSON string from SearchCTIReports
            index: Which report URL to extract (default: 0 for first)

        Returns:
            Extracted URL string
        """
        try:
            import json

            data = json.loads(search_result)

            if "reports" in data and len(data["reports"]) > index:
                url = data["reports"][index]["url"]
                return url

            return "Error: No URL found at specified index in search results"
        except Exception as e:
            return f"Error extracting URL: {str(e)}"

    @traceable(name="cti_fetch_report")
    def fetch_report(self, url: str) -> str:
        """Fetch with universal content cleaning."""
        try:
            import requests
            from bs4 import BeautifulSoup
            import PyPDF2
            import io

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "").lower()

            # Handle PDF files
            if "pdf" in content_type or url.lower().endswith(".pdf"):
                try:
                    pdf_file = io.BytesIO(response.content)
                    pdf_reader = PyPDF2.PdfReader(pdf_file)

                    text_content = []
                    # Extract text from first 10 pages (to avoid excessive content)
                    max_pages = min(len(pdf_reader.pages), 10)

                    for page_num in range(max_pages):
                        page = pdf_reader.pages[page_num]
                        page_text = page.extract_text()
                        if page_text.strip():
                            text_content.append(page_text)

                    if text_content:
                        full_text = "\n\n".join(text_content)
                        # Clean and truncate the text
                        cleaned_text = self._clean_content(full_text)
                        return f"PDF Report Content from {url}:\n\n{cleaned_text[:3000]}..."
                    else:
                        return f"Could not extract readable text from PDF: {url}"

                except Exception as pdf_error:
                    return f"Error processing PDF {url}: {str(pdf_error)}"

            # Handle web pages
            else:
                soup = BeautifulSoup(response.content, "html.parser")

                # Remove unwanted elements
                for element in soup(
                    ["script", "style", "nav", "footer", "header", "aside"]
                ):
                    element.decompose()

                # Try to find main content areas
                main_content = (
                    soup.find("main")
                    or soup.find("article")
                    or soup.find(
                        "div", class_=["content", "main-content", "post-content"]
                    )
                    or soup.find("body")
                )

                if main_content:
                    text = main_content.get_text(separator=" ", strip=True)
                else:
                    text = soup.get_text(separator=" ", strip=True)

                cleaned_text = self._clean_content(text)
                return f"Report Content from {url}:\n\n{cleaned_text[:3000]}..."

        except Exception as e:
            return f"Error fetching report from {url}: {str(e)}"

    def _clean_content(self, text: str) -> str:
        """Clean and normalize text content."""
        import re

        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)

        # Remove common navigation/UI text
        noise_patterns = [
            r"cookie policy.*?accept",
            r"privacy policy",
            r"terms of service",
            r"subscribe.*?newsletter",
            r"follow us on",
            r"share this.*?social",
            r"back to top",
            r"skip to.*?content",
        ]

        for pattern in noise_patterns:
            text = re.sub(pattern, "", text, flags=re.IGNORECASE)

        # Clean up extra spaces again
        text = re.sub(r"\s+", " ", text).strip()

        return text

    @traceable(name="cti_extract_iocs")
    def extract_iocs(self, content: str) -> str:
        """
        Extract Indicators of Compromise from report content using LLM.

        Args:
            content: Report content to analyze

        Returns:
            Structured IOCs in JSON format
        """
        try:
            prompt = IOC_EXTRACTION_PROMPT.format(content=content)
            response = self.llm.invoke(prompt)
            result_text = (
                response.content if hasattr(response, "content") else str(response)
            )
            return result_text
        except Exception as e:
            return json.dumps({"error": str(e), "iocs": []})

    @traceable(name="cti_identify_threat_actors")
    def identify_threat_actors(self, content: str) -> str:
        """
        Identify threat actors, APT groups, and campaigns.

        Args:
            content: Report content to analyze

        Returns:
            Threat actor identification and attribution
        """
        try:
            prompt = THREAT_ACTOR_PROMPT.format(content=content)
            response = self.llm.invoke(prompt)
            result_text = (
                response.content if hasattr(response, "content") else str(response)
            )
            return result_text
        except Exception as e:
            return f"Error identifying threat actors: {str(e)}"

    def extract_mitre_techniques(
        self, content: str, framework: str = "Enterprise"
    ) -> str:
        """
        Extract MITRE ATT&CK techniques from report content using LLM.

        Args:
            content: Report content to analyze
            framework: MITRE framework (Enterprise, Mobile, ICS)

        Returns:
            Structured MITRE techniques in JSON format
        """
        try:
            prompt = MITRE_EXTRACTION_PROMPT.format(
                content=content, framework=framework
            )
            response = self.llm.invoke(prompt)
            result_text = (
                response.content if hasattr(response, "content") else str(response)
            )
            return result_text
        except Exception as e:
            return json.dumps({"error": str(e), "techniques": []})
