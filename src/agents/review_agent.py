import os
import subprocess
import stat
import re
import json
from pathlib import Path
import yaml
import traceback

from typing import Annotated, Literal, List
from typing_extensions import TypedDict

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_deepseek import ChatDeepSeek

from langgraph.graph import StateGraph, START, END
from langchain.agents import AgentExecutor
from langgraph.prebuilt import create_react_agent
from langgraph.graph import MessagesState, END
from langgraph.types import Command

import getpass

from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_text_splitters import RecursiveCharacterTextSplitter, CharacterTextSplitter

from langchain.tools.retriever import create_retriever_tool

from pprint import pprint
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from typing import Annotated
from langgraph.graph.message import add_messages

from langgraph.graph import MessagesState

from langgraph.prebuilt import tools_condition
from langgraph.prebuilt import ToolNode
from IPython.display import Image, display
from langchain_core.runnables.graph import CurveStyle, MermaidDrawMethod, NodeStyles
import paramiko
import pandas as pd
from sklearn.cluster import DBSCAN
from openai import OpenAI
import numpy as np
import argparse

from agents.cwe_agent import llm_cwe_details_retriever_tool
from settings import *
from utils.file_tools import list_dir, read_file, read_file_with_line_numbers
from utils.logging import log_full_conv_message, log_main_conv_message, generate_final_report
from utils.rate_limit_handler import safe_llm_call

def build_review_graph():
    ''' Agent for review the final report and polish the summary of the security analysis '''

    llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="o4-mini")
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    review_tools = [list_dir, read_file, read_file_with_line_numbers, llm_cwe_details_retriever_tool]
    review = llm.bind_tools(review_tools)

    # Nodes of graph
    sys_msg_review_agent = SystemMessage(content=(
    "You are a hardware security expert tasked with reviewing and refining the final security analysis report before it is delivered to the client. "
    "Verify each claimed security issue: if valid, check the reported bug location and revise the report accordingly. "
    "The reported bug location might not be accurate. If not accurate, idewntify the correct location and update the report. "
    "Ensure the final report includes a clear explanation of each bug, the relevant buggy code, the precise location of the issue, and the tools used to identify it."))

    def review_agent(state: MessagesState):
        response = safe_llm_call(review.invoke, [sys_msg_review_agent] + state["messages"])
        
        # If this is the final review (no tool calls), generate the report
        if not response.tool_calls:
            report_path = generate_final_report(response.content)
            log_full_conv_message(f"Final security report generated: {report_path}")
            log_main_conv_message(f"Final security report generated: {report_path}")
        
        return {"messages": [response]}

    def review_tools_condition(state) -> Literal["review_tools", "END"]:
        
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        log_main_conv_message(prev_message.pretty_repr())
        log_main_conv_message(last_message.pretty_repr())
        if len(state["messages"]) > 6:
            return "END"
        elif isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "review_tools"
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("review_agent", review_agent)
    builder.add_node("review_tools", ToolNode(review_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "review_agent")
    builder.add_conditional_edges(
        "review_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        review_tools_condition,
        {"review_tools":"review_tools", "END":END},
    )
    builder.add_edge("review_tools", "review_agent")

    review_graph = builder.compile()

    return review_graph