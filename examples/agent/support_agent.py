"""Support agent (example only). ZeroGraph reads this file with ast; it is never run."""

import subprocess

from langchain.agents import AgentType, initialize_agent
from langchain_community.agent_toolkits import SQLDatabaseToolkit
from langchain_community.tools import RequestsGetTool, ShellTool
from langchain_community.utilities import SQLDatabase
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def restart_service(name: str) -> str:
    """Restart a container by name."""
    return subprocess.run(["docker", "restart", name], capture_output=True, text=True).stdout


@tool
def lookup_order(order_id: str) -> str:
    """Look up an order (pure function, no side effects)."""
    return f"order {order_id}: shipped"


llm = ChatOpenAI(model="gpt-4o-mini")
db = SQLDatabase.from_uri("postgresql://app@db:5432/support")
toolkit = SQLDatabaseToolkit(db=db, llm=llm)

tools = [ShellTool(), RequestsGetTool(requests_wrapper=None), restart_service, lookup_order]
tools += toolkit.get_tools()

support_agent = initialize_agent(tools, llm, agent=AgentType.OPENAI_FUNCTIONS)
