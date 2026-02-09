"""
Bindu Docs QA Agent 🌻
Answers questions about Bindu documentation.
"""

import os
from dotenv import load_dotenv

load_dotenv()

from bindu.penguin.bindufy import bindufy
from agno.agent import Agent, RunResponse
from agno.models.openrouter import OpenRouter
from agno.tools.duckduckgo import DuckDuckGoTools

# ---------------------------------------------------------------------------
# Agent Configuration
# ---------------------------------------------------------------------------
agent = Agent(
    name="Bindu Docs Agent",
    instructions="""
    You are an expert assistant for Bindu (GetBindu).
    
    TASK:
    1. Search the Bindu documentation (docs.getbindu.com) for the user's query.
    2. Answer the question clearly.
    
    FORMATTING RULES:
    - Return your answer in CLEAN Markdown.
    - Use '##' for main headers.
    - Use bullet points for lists.
    - Do NOT wrap the entire response in JSON code blocks. Just return the text.
    - At the end, include a '### Sources' section with links found.
    """,
    model=OpenRouter(
        id="openai/gpt-oss-120b",
        api_key=os.getenv("OPENROUTER_API_KEY"),
    ),
    tools=[DuckDuckGoTools()],
    markdown=True,
)

# ---------------------------------------------------------------------------
# Handler (FIXED)
# ---------------------------------------------------------------------------
def handler(data):
    """
    1. Parses input from Bindu (handles dict or string).
    2. Runs the Agno agent.
    3. Returns ONLY the content string (removes technical metadata).
    """
    print(f"Incoming Data: {data}")
    
    # --- Step 1: Clean Input ---
    # Bindu might send a dict like {'content': '...'} or a direct string
    user_query = ""
    if isinstance(data, dict):
        # Try to find the message content in common fields
        user_query = data.get("content") or data.get("message") or str(data)
    else:
        user_query = str(data)

    # --- Step 2: Get Response ---
    # agent.run returns a RunResponse object, NOT a string
    response: RunResponse = agent.run(user_query)

    # --- Step 3: Format Output ---
    # We extract strictly the .content attribute
    if response and hasattr(response, 'content'):
        return response.content
    
    # Fallback if something goes wrong
    return "Error: No content received from the agent."

# ---------------------------------------------------------------------------
# Bindu config
# ---------------------------------------------------------------------------
config = {
    "author": "your.email@example.com",
    "name": "bindu_docs_agent",
    "description": "Answers questions about Bindu documentation",
    "deployment": {"url": "http://localhost:3773", "expose": True},
    "skills": [],
}

# Run the Bindu wrapper
bindufy(config, handler)