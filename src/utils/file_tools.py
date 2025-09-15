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

from utils.budget import update_budget
from utils.logging import log_action_message
from utils.rate_limit_handler import safe_llm_call

@tool
def read_file_with_line_numbers(file_path: str) -> str:
    """Reads a file and returns its content with line numbers.
       This is best for code files like .sv files to have line numbers for each line."""
    # log things
    log_action_message(f"Reading file with line numbers: {file_path}")
    update_budget('read_file_with_line_numbers')
    #print(f"Reading file with line numbers: {file_path}")
    with open(file_path, 'r', errors='ignore') as file:
        lines = file.readlines()
    numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
    return "".join(numbered_lines)

# tool to explore folder content
@tool
def list_dir(
    dir_path: Annotated[str, "Path to the directory to list"],
) -> str:
    """Use this tool to list the content of a directory."""
    # log things
    log_action_message(f"Listing directory: {dir_path}")
    update_budget('list_dir')
    # check if file exists
    if not os.path.exists(dir_path):
        return "Directory does not exist."
    
    # list the content of the directory
    dir_content = os.listdir(dir_path)
    # print(files)
    # classify files and directories
    files = " ".join([f for f in dir_content if os.path.isfile(os.path.join(dir_path, f))])
    dirs = " ".join([d for d in dir_content if os.path.isdir(os.path.join(dir_path, d))])
    # format the response
    response = f"Files in {dir_path}:\n{files}\n\nDirectories in {dir_path}:\n{dirs}"
    # print(response)
    return response

# read content of a file
@tool
def read_file(
    file_path: Annotated[str, "Path to the file to read"],
) -> str:
    """Use this tool to read the content of a file.
       This is best for documentation files like .md files to have the content of the file unaltered."""
    # log things
    log_action_message(f"Reading file: {file_path}")
    update_budget('read_file')
    # check if file exists
    if not os.path.exists(file_path):
        return "File does not exist."
    
    # read the content of the file
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    
    return content

@tool
def read_file_from_host(file_path: Annotated[str, "absolute path of file to read"]) -> str:
    """Use this tool to read the content of a file from the host machine. Use absolute paths."""
    pwd = os.environ["PWD_SRV"]
    host = "XXXX-1"
    username = "XXXX-2"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=pwd)
    # get the list of tests
    cmd = f"cat {file_path}"
    r_stdin, r_stdout, r_stderr = ssh.exec_command(cmd)

    exit_status = r_stdout.channel.recv_exit_status()

    if(exit_status != 0):
        print("Error running command")
        print(cmd)
        return "Error: "+r_stderr.read().decode()
    file_content = "\n".join(r_stdout.read().decode().split('\n')[1:])
    
    return file_content

@tool
def list_dir_from_host(dir_path: Annotated[str, "Path (absolute) to the directory to list"]) -> str:
    """Use this tool to list the content of a directory from the host machine. Use absolute paths."""
    pwd = os.environ["PWD_SRV"]
    host = "XXXX-1"
    username = "XXXX-2"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=pwd)
    # get the list of tests
    cmd = f"ls {dir_path}"
    r_stdin, r_stdout, r_stderr = ssh.exec_command(cmd)

    exit_status = r_stdout.channel.recv_exit_status()

    if(exit_status != 0):
        print("Error running command")
        print(cmd)
        return "Error: "+r_stderr.read().decode()
    dir_content = "\n".join(r_stdout.read().decode().split('\n')[1:])
    
    return dir_content