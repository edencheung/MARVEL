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

from settings import *
from utils.file_tools import list_dir, read_file
from utils.budget import update_budget
from utils.logging import log_action_message, log_full_conv_message
from utils.rate_limit_handler import exponential_backoff_retry, safe_llm_call


# Run bazel query and get list of tests
def get_verilator_tests(ip: str) -> str:
    # Run the bazel query command locally to get the list of tests
    cmd = f"{SOC_BASE_DIR}/bazelisk.sh query 'attr(tags,verilator,tests(//sw/...))'"
    full_cmd = f"cd {SOC_BASE_DIR} && {cmd}"
    try:
        print (f"Running command: {full_cmd}")
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, executable="/bin/bash")
        if result.returncode != 0:
            print("Error running command")
            print(full_cmd)
            return []
        tests = result.stdout.split('\n')
        tests = [test for test in tests if test != '' and ip in test and "rom_ext" not in test]
        print(f"Found {len(tests)} verilator tests for {ip}")
        print("\n".join(tests))
        return tests
    except Exception as e:
        print(f"Exception running bazel query: {e}")
        return []

@tool
def run_verilator_tests(ip: str) -> str:
    """Use this tool to execute verilator tests for the given ip.
       Returns a list of executed tests and their status.
       Note: some tests will TIMEOUT, and this is due to machine constraints. Just ignore these tests."""
    #log things
    log_action_message(f"Running verilator tests for {ip}")
    # get the list of tests
    tests = get_verilator_tests(ip)
    if len(tests) == 0:
        return "No verilator tests found for this IP."
    # run the tests locally
    cmd = f"{SOC_BASE_DIR}/bazelisk.sh test" + " "
    cmd += " ".join(tests)
    full_cmd = f"cd {SOC_BASE_DIR} && {cmd} 2>&1"
    try:
        result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, executable="/bin/bash", env=os.environ.copy())
        output = result.stdout
        print("OUTPUT:")
        print(output)
        return output.split("INFO:")[-1]
    except Exception as e:
        print("ERROR:")
        print(e)
        return f"Error running verilator tests: {str(e)}"


def build_verilator_graph():
    llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)

    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="gpt-4.1", temperature=TEMP)
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    verilator_tools = [run_verilator_tests, list_dir, read_file]

    llm_verilator_checker = llm.bind_tools(verilator_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_verilator_agent = SystemMessage(content=""""You are a helpful assistant tasked with testing RTL code for security issues using verilator tests.
                                               You have access to a tool to run the verilator tests of a specific IP.
                                               Given the output of the verilator tests, look into the logs of failed ones and determine if there are security issues in the RTL.""")
    def verilator_agent(state: MessagesState):
        return {"messages": [safe_llm_call(llm_verilator_checker.invoke, [sys_msg_verilator_agent] + state["messages"])]}

    def verilator_tools_condition(state) -> Literal["verilator_tools", "END"]:
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        if isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "verilator_tools"
        
        return "END"

    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("verilator_agent", verilator_agent)
    builder.add_node("verilator_tools", ToolNode(verilator_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "verilator_agent")
    builder.add_conditional_edges(
        "verilator_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        verilator_tools_condition,
        {"verilator_tools":"verilator_tools", "END":END},
    )
    builder.add_edge("verilator_tools", "verilator_agent")


    # graph = None
    verilator_graph = builder.compile()
    return verilator_graph

verilator_graph = build_verilator_graph()


@tool
def run_verilator_agent(
    ip: Annotated[str, "IP name to run verilator tests on"],
) -> str:
    """Use this tool to execute verilator tests for the given ip and analyze the results."""    # log things
    log_action_message(f"Running verilator agent on {ip}")
    update_budget('run_verilator_agent')
    
    # Create the instruction for the linter agent
    instruction = f"""Run a security analysis on the {ip} IP.

    Inspect the logs of failing runs and determine if there are security issues in the RTL.
    If any security issues are found, provide a detailed explanation of the issue and its location in the RTL code."""

    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = verilator_graph.invoke({"messages": message}, {"recursion_limit": 200})

    return result['messages'][-1].content