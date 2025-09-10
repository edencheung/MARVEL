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
from utils.file_tools import read_file_with_line_numbers
from utils.budget import update_budget
from utils.logging import log_action_message, log_full_conv_message

@tool
def similar_bug_tool(bug:str, ip_file: str) -> str:
    """ Use this tool to look for bugs similar to previously found bugs. 
        Pass bug line and a file path to search for similar bugs.
        Returns a list of similar bug lines with line numbers.
    """
    # log things
    log_action_message(f"Running similar bug tool on {ip_file} for bug: {bug}")
    # check if file exists
    if(not os.path.exists(ip_file)):
        log_action_message(f"file not exist {ip_file}")
        return "File does not exist."
    
    # read ip_file
    with open(ip_file, 'r') as f:
        ip_file_content = f.read()
    ip_lines = ip_file_content.split('\n')
    # strip all lines in ip_lines
    ip_lines = [line.strip() for line in ip_lines]

    text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        separators=['\n'],
        chunk_size=30,
        chunk_overlap=0,
    )
    documents = [Document(page_content=open(ip_file,'r').read()) ]
    doc_splits = text_splitter.split_documents(documents)
    # Add to vectorDB
    vectorstore = InMemoryVectorStore.from_documents(
        documents=doc_splits,
        collection_name="lint_tags",
        embedding=OpenAIEmbeddings(),
    )
    # Create retriever
    retriever = vectorstore.as_retriever(search_kwargs={"k": 10})
    result = retriever.invoke(bug)

    # for each result find line number and build response
    response = ""
    for r in result:
        # get the line number
        line_number = ip_lines.index(r.page_content.strip()) + 1
        # add to result
        response += f"\nFound similar bug in {ip_file} at line {line_number}: {r.page_content}"
    return response

def build_similar_bug_graph():
    if MODEL == "openai":
        llm = ChatOpenAI(model="gpt-4.1-mini", temperature=TEMP)
    elif MODEL == "sonnet": 
        llm = ChatAnthropic(model="claude-3-5-haiku-latest", temperature=TEMP)
    else:
        llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    similar_bug_tools = [similar_bug_tool, read_file_with_line_numbers]

    llm_similar_bug = llm.bind_tools(similar_bug_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_similar_bug_agent = SystemMessage(content="""You are a helpful assistant tasked with identify bug instances similar to given bugs in the provided RTL code. 
    Identify lines with similar code by providing the full bug line to the tool.
    Multiple identified lines might not be actual bugs.
    Analyze the identified lines and determine if they are indeed bugs.
    Only reply with a list of buggy lines with line numbers.""")

    def similar_bug_agent(state: MessagesState):
        log_full_conv_message(state["messages"][-1].pretty_repr())
        return {"messages": [llm_similar_bug.invoke([sys_msg_similar_bug_agent] + state["messages"])]}

    def similar_bug_tools_condition(state) -> Literal["similar_bug_tools", "END"]:
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        if isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "similar_bug_tools"
        
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("similar_bug_agent", similar_bug_agent)
    builder.add_node("similar_bug_tools", ToolNode(similar_bug_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "similar_bug_agent")
    builder.add_conditional_edges(
        "similar_bug_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        similar_bug_tools_condition,
        {"similar_bug_tools":"similar_bug_tools", "END":END},
    )
    builder.add_edge("similar_bug_tools", "similar_bug_agent")

    # builder.add_edge("lint_checker_agent", END)

    # graph = None
    similar_bug_graph = builder.compile()
    return similar_bug_graph

similar_bug_graph = build_similar_bug_graph()

@tool
def run_similar_bug_agent(
    bug: Annotated[str, "Bug line to check for"],
    file_path: Annotated[str, "Path to the RTL file"],
) -> str:
    """Use this tool to run the similar bug agent on the given RTL code. This tool is useful to check for bugs similar to previously detected ones in the RTL code.
        Best to use on the same file or equivalent files of different IPs in which a bug was found.
        The bug should be a line of code that was previously detected as a bug."""
    log_action_message(f"Running similar bug agent on {file_path} for bug: {bug}")
    update_budget('run_similar_bug_agent')
    # check if file exists
    if not os.path.exists(file_path):
        return "File does not exist."
    # Create the instruction for the similar bug agent
    instruction = f"""This bug was previously found in another file of this design:
    {bug}
    
    Please check the RTL code in the file {file_path} for similar bugs."""
    
    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = similar_bug_graph.invoke({"messages": message})
    # # log the run
    # with open('similar_bug_agent_run.log', 'a') as log:
    #     log.write(f"Bug line: {bug}\n")
    #     log.write(f"File path: {file_path}\n")
    #     log.write(f"Instruction: {instruction}\n")
    #     log.write(f"Result:\n")
    #     for m in result['messages']:
    #         log.write(m.pretty_repr())
    #     log.write("\n\n")
    
    return result['messages'][-1].content