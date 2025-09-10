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

SOC_BASE_DIR = "/home/XXXX-2/hackdate"

class MessagesState(MessagesState):
    # Add any keys needed beyond messages, which is pre-built 
    pass

#################################################################################
# --------------------------------- Logging ----------------------------------- #
#################################################################################
# parse arguments for IP
parser = argparse.ArgumentParser(description='Agentic Security Analysis')
parser.add_argument('--ip', type=str, default="all", help='IP to analyze. If not specified analyzes whole SOC')
parser.add_argument('--model', type=str, default="deepseek", choices=["openai", "deepseek", "sonnet"], help='Model to use. Can be openai - deepseek - sonnet')
# add option to run a specific agent
parser.add_argument('--agent', type=str, default="agentic", choices=["anomaly", "verilator", "assertion", "linter", "agentic", "cwe", "similar_bug"], help='Agent to run. Can be verilator - assertions - linter - agentic - cwe - similar_bug')
parser.add_argument('--design_file', type=str, default="", help='Design file to analyze. Required for assertions, linter, similar bug and cwe agents')
parser.add_argument('--top_module', type=str, default="", help='Top module name. Required for assertions, linter, and cwe agents')
parser.add_argument('--security_objective', type=str, default="", help='Security objective to check for. Required for assertions, linter and cwe agents')
parser.add_argument('--bug_example', type=str, default="", help='Bug example to check for. Required for similar bug agent')
parser.add_argument('--temp', type=float, default=0.2, help='Temperature for the model. Default is 0.5')

args = parser.parse_args()
IP = args.ip
MODEL = args.model
AGENT = args.agent
TOP_MODULE = args.top_module
DESIGN_FILE = args.design_file
SECURITY_OBJECTIVE = args.security_objective
BUG = args.bug_example
TEMP = args.temp


if IP == "all":
    IP_STRING = "whole"
    FOCUS_STRING = "Make sure to analyze the whole SOC and not just some IPs. You can find higher level documentation in hw/doc to understand the whole SOC."
else:
    IP_STRING = f"{args.ip} IP of the"
    FOCUS_STRING = f"Focus on the {args.ip} IP and make sure to analyze it thoroughly."

full_conv_log = open(f'{IP}_{MODEL}_{AGENT}_{TOP_MODULE}_{TEMP}_full_conv_log.txt','w')
def log_full_conv_message(message: str):
    """Log a message to the full conversation log."""
    full_conv_log.write(message+'\n')
    full_conv_log.flush()

main_conv_log = open(f'{IP}_{MODEL}_{AGENT}_{TOP_MODULE}_{TEMP}_main_conv_log.txt','w')
def log_main_conv_message(message: str):
    """Log a message to the main conversation log."""
    main_conv_log.write(message+'\n')
    main_conv_log.flush()

actions_log = open(f'{IP}_{MODEL}_{AGENT}_{TOP_MODULE}_{TEMP}_actions_log.txt','w')
def log_action_message(message: str):
    """Log a message to the actions log."""
    actions_log.write(message+'\n')
    actions_log.flush()

#################################################################################
# ------------------------------- Helper Functions ---------------------------- #
#################################################################################
budget = 3000
cost_of_actions = {}
cost_of_actions['run_verilator_agent'] = 25
cost_of_actions['run_assertions_checker_agent'] = 20
cost_of_actions['run_linter_agent'] = 10
cost_of_actions['run_similar_bug_agent'] = 10
cost_of_actions['list_dir'] = 1
cost_of_actions['read_file'] = 1
cost_of_actions['read_file_with_line_numbers'] = 1
cost_of_actions['run_llm_cwe_checker_agent'] = 10

def update_budget(action: str):
    """Update the budget based on the action taken."""
    global budget
    if action in cost_of_actions:
        budget -= cost_of_actions[action]
    else:
        print(f"Action {action} not found in cost of actions.")
    return budget

def is_budget_exceeded():
    """Check if the budget is exceeded."""
    global budget
    if budget < 0:
        log_action_message(f"Budget exceeded: {budget}")
        return True
    return False

def error_string(ex: Exception) -> str:
    return '\n'.join([
        ''.join(traceback.format_exception_only(None, ex)).strip(),
        ''.join(traceback.format_exception(None, ex, ex.__traceback__)).strip()
    ])

#################################################################################
# ------------------------------- Utility Tools ------------------------------- #
#################################################################################
@tool
def read_file_with_line_numbers(file_path: str) -> str:
    """Reads a file and returns its content with line numbers.
       This is best for code files like .sv files to have line numbers for each line."""
    # log things
    log_action_message(f"Reading file with line numbers: {file_path}")
    update_budget('read_file_with_line_numbers')
    #print(f"Reading file with line numbers: {file_path}")
    with open(file_path, 'r') as file:
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
    with open(file_path, 'r') as f:
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

################################################################################
# ------------------------------ VC Lint Agent ------------------------------- #
################################################################################
def gen_opentitan_filelist(p,m):

    # print(p)
    # if fusesoc.conf file exists, delete it
    if(os.path.exists("fusesoc.conf")):
        os.remove("fusesoc.conf")
    # if build directory exists, delete it
    # if(os.path.exists("build")):
    #     cmd = "rm -rf build"
    #     subprocess.run(cmd.split(' '))

    # add opentitan libray of cores to fusesoc
    cmd = f"fusesoc library add opentitan-cores {SOC_BASE_DIR}/hw"
    subprocess.run(cmd.split(' '))
    # print(cmd)

    # directory containing the core file
    p_str = str(p)
    core_dir = p_str[:p_str.find('/rtl/')]
    # core_dir = Path('opentitan').joinpath(p.parent).parent # assuming file is in rtl/buggyfile.sv
    # print("core dir: "+str(core_dir))

    # get the core files in core 
    core_files  = []
    for file in os.listdir(core_dir):
        if file.endswith(".core"):
            # print(os.path.join(core_dir, file))
            core_files.append(os.path.join(core_dir, file))
    # print("core files:\n"+str(core_files))
    # identify the correct core file by traversing using yaml parser and get the identifier for the core
    flags = set()
    if('/ip/' in p_str):
        flags.add('fileset_ip')
    identifier_core = ''
    relevant_core_file=''
    found=False
    for core_file in core_files:
        if(not os.path.exists(core_file) ):
            return ''
        with open(core_file,'r') as f:
            core_yaml = yaml.safe_load(f)
            files = core_yaml["filesets"]["files_rtl"]["files"]
            for file in files:
                if (m in file): # this is the right core file
                    identifier_core = core_yaml["name"] # get the identifier for the core
                    found=True
                    break
            if(found):
                for file in files: # get flags
                    # check if there is a flag
                    # get that flag
                    # update flag ommand string
                    if ("?" in file):
                        flag = file[:file.find('?')]
                        flag=flag.replace("\"","")
                        flag=flag.replace(" ","")
                        flags.add(flag)
        if (found):
            relevant_core_file = core_file
            break

    # print("relevant_core_file: "+relevant_core_file)
    # print("identifier_core: "+identifier_core)
    
    # run the fusesoc run setup command
    flag_command = ''
    for flag in flags:
        flag_command = flag_command + "--flag "+flag+" "
    # make sure top level exists
    if (not 'toplevel' in core_yaml["targets"]["default"]):
        # create toplevel
        core_yaml["targets"]["default"]["toplevel"]= m
        # write core_yaml to relevant corefile
        if(not os.path.exists(relevant_core_file) ):
            return ''
        with open(relevant_core_file, 'w',) as f :
            yaml.dump(core_yaml,f,sort_keys=False)
    elif(core_yaml["targets"]["default"]["toplevel"]==''):
        core_yaml["targets"]["default"]["toplevel"]= m
        if(not os.path.exists(relevant_core_file) ):
            return ''
        with open(relevant_core_file, 'w',) as f :
            yaml.dump(core_yaml,f,sort_keys=False)

    cmd = "fusesoc run --setup --tool=vcs "+flag_command+identifier_core
    subprocess.run(cmd.split(' '))
#     log.write(cmd+'\n')
#     log.flush()

    # extract the path of .scr file
    scr_filepath = Path('build').joinpath(identifier_core.replace(':','_'),'default-vcs',identifier_core.replace(':','_')+'.scr')
    #print(scr_filepath)

    return str(scr_filepath)


@tool
def lint_checker_tool(design_filepath: str, top_module: str, lint_tags: List[str]):
    
    """Use this tool to execute VC SpyGlass Lint lint_checks on the top_module.
    It takes the path to a verilog file, the top module name, and a list of lint tags to check."""
    # log things
    log_action_message(f"Running lint checker tool on {design_filepath} for {top_module} with lint tags: {lint_tags}")

    result = ""
    try:
        # get all relevant files
        scr_filepath = gen_opentitan_filelist(design_filepath,top_module)
        src_files = open(scr_filepath,'r').read()    
        src_files = src_files.replace('../',scr_filepath[:scr_filepath.find('default-vcs/')])   
        fw = open('filelist_'+top_module+'.txt','w')
        fw.write(src_files)
        fw.close()
        
        # form tcl script for vc_static

        tcl_template_file = 'vcst_template.tcl' 
        tcl_template_content = open(tcl_template_file,'r').read()

        lint_checks = '\n'.join([ 'configure_lint_tag -enable -tag \"' + tag + '\" -severity Error' for tag in lint_tags ])
        tcl_template_content = tcl_template_content.replace('[LINT_TAGS]',lint_checks)

        tcl_template_content = tcl_template_content.replace('[TOP_MODULE]',top_module)
        tcl_template_content = tcl_template_content.replace('[FILELIST]','filelist_'+top_module+'.txt')
        results_file = 'results_vcst_'+top_module+'.txt'
        tcl_template_content = tcl_template_content.replace('[RESULT_FILE]',results_file)

        tcl_script = 'vcst_'+top_module+'.tcl'
        wf = open(tcl_script,'w')
        wf.write(tcl_template_content)
        wf.close()
        
        # run tcl script
        wf = open('run_vcst.sh','w')
        cmd = "vc_static_shell -batch -no_ui -f "+ tcl_script
        wf.write(cmd)
        wf.close()

        os.chmod('run_vcst.sh',stat.S_IRWXU)
        subprocess.run('./run_vcst.sh',shell=True, capture_output=True, text=True)
        
        result = open(results_file,'r').read()
        
    except BaseException as e:
        # print stack trace
        print(error_string(e))
        return f"Failed to execute. Error: {repr(e)}\n{error_string(e)}"
    
    result_str = f"Successfully executed:\n```lint checker tool\n```\nOutput: {result}"
    
    return result_str

def build_lint_graph():
    lint_tags_description_filename = 'all_lint_tags_descriptions.txt'
    documents = [Document(page_content=open(lint_tags_description_filename,'r').read()) ]
    text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        separators=['\n'],
        chunk_size=15,
        chunk_overlap=0,
    )
    doc_splits = text_splitter.split_documents(documents)
    # Add to vectorDB
    vectorstore = InMemoryVectorStore.from_documents(
        documents=doc_splits,
        collection_name="lint_tags",
        embedding=OpenAIEmbeddings(),
    )

    lint_tag_retriever = vectorstore.as_retriever(search_kwargs={"k": 20})
    llm = ChatOpenAI(model="gpt-4.1-mini", temperature=TEMP)

    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="gpt-4.1-mini", temperature=TEMP)
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-5-haiku-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    lint_tag_retriever_tool = create_retriever_tool(
        lint_tag_retriever,
        "retrieve_relevant_lint_tags",
        "Search and return relevant lint tags pertaining to the security issue being analyzed.",
    )

    linter_tools = [lint_tag_retriever_tool, lint_checker_tool]

    llm_lint_checker = llm.bind_tools(linter_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_lint_checker_agent = SystemMessage(content="You are a helpful assistant tasked with testing RTL code for security issues using lint checks.")
    def lint_checker_agent(state: MessagesState):
        return {"messages": [llm_lint_checker.invoke([sys_msg_lint_checker_agent] + state["messages"])]}

    def lint_tools_condition(state) -> Literal["linter_tools", "END"]:
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        if isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "linter_tools"
        
        return "END"

    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("lint_checker_agent", lint_checker_agent)
    builder.add_node("linter_tools", ToolNode(linter_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "lint_checker_agent")
    builder.add_conditional_edges(
        "lint_checker_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        lint_tools_condition,
        {"linter_tools":"linter_tools", "END":END},
    )
    builder.add_edge("linter_tools", "lint_checker_agent")

    # builder.add_edge("lint_checker_agent", END)

    # graph = None
    lint_graph = builder.compile()
    return lint_graph

lint_graph = build_lint_graph()


@tool
def run_linter_agent(
    design_filepath: Annotated[str, "Path to the RTL file"],
    top_module: Annotated[str, "Top module name"],
    security_objective: Annotated[str, "Security objective to check for"],
) -> str:
    """Use this tool to run the linter agent on the given RTL code. The security objective could be FSM, uninitialized registers, incorrectly instantiated modules, etc."""
    # log things
    log_action_message(f"Running linter agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    update_budget('run_linter_agent')
    # check if file exists
    if not os.path.exists(design_filepath):
        return "File does not exist."
    file_content = open(design_filepath, 'r').read()
    # Create the instruction for the linter agent
    instruction = f"""Are there security concerns related to {security_objective} in the provided RTL:
    The design filepath is:

    {design_filepath}

    And the top module is:

    {top_module}

    The RTL code is:
    '''verilog
    {file_content}
    '''

    Identify relevant lint tags for the RTL to be checked for.
    Then run the tests using the linting tool.
    From the output of the linting tool, determine if there are security issues in the RTL."""

    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = lint_graph.invoke({"messages": message})

    return result['messages'][-1].content

#################################################################################

if AGENT == "linter":
    log_full_conv_message(f"Running linter agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_linter_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    #run_linter_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)


#################################################################################
# ------------------------------ Verilator Tool ------------------------------- #
#################################################################################
# Run bazel query and get list of tests
def get_verilator_tests(ip: str) -> str:
    pwd = os.environ["PWD_SRV_NYU"]
    host = "XXXX-1"
    username = "XXXX-2"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=pwd)
    # get the list of tests
    cmd = f"{SOC_BASE_DIR}/bazelisk.sh query 'tests(//sw/...) except attr(tags, cw310, tests(//...))  except attr(tags, cw340, tests(//...)) except attr(tags, dv, tests(//...))'"
    cmd = f"cd {SOC_BASE_DIR} && "+cmd
    r_stdin, r_stdout, r_stderr = ssh.exec_command(cmd)

    exit_status = r_stdout.channel.recv_exit_status()

    if(exit_status != 0):
        print("Error running command")
        print(cmd)
        return []
    tests = r_stdout.read().decode().split('\n')
    tests = [test for test in tests if test != '' and ip in test and "rom_ext" not in test]
    ssh.close()
    return tests

@tool
def run_verilator_tests(ip: str) -> str:
    """Use this tool to execute verilator tests for the given ip.
       Returns a list of executed tests and their status."""
    #log things
    log_action_message(f"Running verilator tests for {ip}")
    # get the list of tests
    tests = get_verilator_tests(ip)
    #print(tests)
    pwd = os.environ["PWD_SRV_NYU"]
    host = "XXXX-1"
    username = "XXXX-2"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=pwd)
    if(len(tests) == 0):
        return "No verilator tests found for this IP."
    # run the tests
    cmd = f"{SOC_BASE_DIR}/bazelisk.sh test --test_timeout=320 "
    cmd += " ".join(tests)
    cmd = f"""bash -c "cd {SOC_BASE_DIR} && {cmd} 2>&1" """
    #print(cmd)
    r_stdin, r_stdout, r_stderr = ssh.exec_command(cmd)

    exit_status = r_stdout.channel.recv_exit_status()

    return r_stdout.read().decode().split("INFO:")[-1]


def build_verilator_graph():
    if MODEL == "openai":
        llm = ChatOpenAI(model="gpt-4.1", temperature=TEMP)
    elif MODEL == "sonnet":
        llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    else:
        llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    verilator_tools = [run_verilator_tests, list_dir_from_host, read_file_from_host]

    llm_verilator_checker = llm.bind_tools(verilator_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_verilator_agent = SystemMessage(content=""""You are a helpful assistant tasked with testing RTL code for security issues using verilator tests.
                                               You have access to a tool to run the verilator tests of a specific IP.
                                               Given the output of the verilator tests, look into the logs of failed ones and determine if there are security issues in the RTL.""")
    def verilator_agent(state: MessagesState):
        return {"messages": [llm_verilator_checker.invoke([sys_msg_verilator_agent] + state["messages"])]}

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
    result = verilator_graph.invoke({"messages": message})

    return result['messages'][-1].content

#################################################################################
####################################################################################################
# ------------------------------------------ Test ------------------------------------------------ #
####################################################################################################
if AGENT == "verilator":
    log_full_conv_message(f"Running verilator agent on {IP}")
    run_verilator_agent.invoke({"ip": IP})


#################################################################################
# ------------------------------ Assertion Agent ------------------------------ #
#################################################################################
@tool
def assertion_checker_tool(design_filepath: str, top_module: str, assertions: dict, clock_signal: str,\
                           reset_signal: str, reset_active: Literal["low", "high"]):
    
    """Use this tool to execute VC Formal assertions on the top_module."""
    # log thingsq
    log_action_message(f"Running assertion checker tool on {design_filepath} for {top_module} with assertions: {assertions}")
    result = ""
    try:
        # get all relevant files
        scr_filepath = gen_opentitan_filelist(design_filepath,top_module)
        src_files = open(scr_filepath,'r').read()    
        src_files = src_files.replace('../',scr_filepath[:scr_filepath.find('default-vcs/')])   
        filelist = 'filelist_'+top_module+'.txt'
        fw = open(filelist,'w')
        fw.write(src_files)
        fw.close()
        
        # form tcl script for vc_formal

        tcl_template_file = 'vcf_template.tcl' 
        tcl_template_content = open(tcl_template_file,'r').read()

        tcl_template_content = tcl_template_content.replace('[TOP_MODULE]',top_module)
        tcl_template_content = tcl_template_content.replace('[FILELIST]',filelist)
        tcl_template_content = tcl_template_content.replace('[CLK]',clock_signal)
        tcl_template_content = tcl_template_content.replace('[RST]',reset_signal)
        tcl_template_content = tcl_template_content.replace('[RST_ACTIVE]',reset_active)
        
        results_file = 'results_vcf_'+top_module+'.txt'
        tcl_template_content = tcl_template_content.replace('[RESULT_FILE]',results_file)

        tcl_script = 'vcf_'+top_module+'.tcl'
        wf = open(tcl_script,'w')
        wf.write(tcl_template_content)
        wf.close()
        
        
        # insert assertions to source RTL
        assertions_str = '\n\n'.join(assertions.values())
        design_content = open(design_filepath,'r').read()
        design_content = design_content.replace("endmodule","\n"+assertions_str+"\n\nendmodule")
        # save the edited design RTL as a copy <design>_assertion-inserted.sv
        design_basename = os.path.basename(design_filepath)
        design_basename, extension = design_basename.split('.')
        assertion_inserted_filename = design_filepath[:design_filepath.find(design_basename)] + design_basename + '_assertion-inserted.'+extension
        #print(assertion_inserted_filename)
        wf = open(assertion_inserted_filename,'w')
        wf.write(design_content)
        wf.close()
            
        # change the source filename in filelist
        filelist_content = open(filelist,'r').read()
        filelist_content = re.sub(r'.*'+top_module+'.'+extension,assertion_inserted_filename,filelist_content)
        fw = open(filelist,'w')
        fw.write(filelist_content)
        fw.close()

        # run tcl script
        wf = open('run_vcf.sh','w')
        cmd = "vcf -batch -no_ui -f "+ tcl_script
        wf.write(cmd)
        wf.close()
    # echo "[$end_ts] Finished analysis for $ip" >> $run_log
        os.chmod('run_vcf.sh',stat.S_IRWXU)
        subprocess.run('./run_vcf.sh',shell=True, capture_output=True, text=True)
        
        results_content = open(results_file,'r').read()
        
        # parse output file to obtain falsified assertions' name, location, string
        # get all properties
        results_content = results_content[results_content.find("Property Verbose List:"):]
        # security assertion list
        security_assertion_details = re.findall(r"ID:[\S\s\n]+?engine", results_content)
        # get falsified properties
        falsified_properties = {}
        for sa in security_assertion_details:
            if "falsified" in sa:
                match = re.search(r"name\s+:\s+(.+)",sa)
                if match:
                    name = match.group(1).strip()
                    name = name[name.rfind('.')+1:]

                    falsified_properties[name] = assertions[name]  

        if len(falsified_properties) >0:
            result = 'The following properties were falsified:\n' + '\n\n'.join(falsified_properties.values())
        else:
            result = "There are no falsified properties."
        
        
    except BaseException as e:
        return f"Failed to execute. Error: {repr(e)}\n{error_string(e)}"
    
    result_str = f"Successfully executed:\n```assertion checker tool\n```\nOutput:\n {result}"
    
    return result_str

def build_assertion_graph():
    if MODEL == "openai":
        llm = ChatOpenAI(model="gpt-4o", temperature=0)
    elif MODEL == "sonnet":
        llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=0)
    else:
        llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    assertion_checker_tools = [assertion_checker_tool]
    llm_assertion_checker = llm.bind_tools(assertion_checker_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_assertion_checker_agent = SystemMessage(content="You are a helpful assistant tasked with testing RTL code for security issues using assertions.")
    def assertion_checker_agent(state: MessagesState):
        return {"messages": [llm_assertion_checker.invoke([sys_msg_assertion_checker_agent] + state["messages"])]}

    def assertion_tools_condition(state) -> Literal["assertion_checker_tools", "END"]:
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        if len(state["messages"]) > 6:
            return "END"
        elif isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "assertion_checker_tools"
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("assertion_checker_agent", assertion_checker_agent)
    builder.add_node("assertion_checker_tools", ToolNode(assertion_checker_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "assertion_checker_agent")
    builder.add_conditional_edges(
        "assertion_checker_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        assertion_tools_condition,
        {"assertion_checker_tools":"assertion_checker_tools", "END":END},
    )
    builder.add_edge("assertion_checker_tools", "assertion_checker_agent")

    assertions_checker_graph = builder.compile()
    return assertions_checker_graph

assertions_checker_graph = build_assertion_graph()

@tool
def run_assertions_checker_agent(
    design_filepath: Annotated[str, "Path to the RTL file"],
    top_module: Annotated[str, "Top module name"],
    security_objective: Annotated[str, "Security objective to check for"],
) -> str:
    """Use this tool to run the assertions checker agent on the given RTL code."""
    # log things
    log_action_message(f"Running assertions checker agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    update_budget('run_assertions_checker_agent')
    # print(f"Running assertions checker agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    # check if file exists
    if not os.path.exists(design_filepath):
        return "File does not exist."
    file_content = open(design_filepath, 'r').read()
    
    example_assertions_structure = "assertions = {\"assertion_p1\":\"property p1;\\n    @(posedge clk) signal_A |-> signal_B;\\nendproperty\nassertion_p1: assert property (p1);\", \"assertion_p2\":\"property p2;\\n    @(posedge clk) conditions |-> signal_C;\\nendproperty\\nassertion_p2: assert property (p2);\"}"
    
    
    # Create the instruction for the assertions checker agent
    instruction = f"""Are there security concerns related to {security_objective} in the provided RTL:
    The design filepath is:

    {design_filepath}

    And the top module is:

    {top_module}

    The RTL code is:
    '''verilog
    {file_content}
    '''

    Form relevant system verilog assertions for the RTL to be checked for.
    These system verilog assertions should be in a dict with the key as the name and the value as the assertion string.
    An example assertions object to be sent to assertion checker tool is as follows:

    {example_assertions_structure}

    Then run the assertions using the assertion checker tool. This tool call must include the assertions dictionary as an argument.
    From the output of the assertion checker tool, determine if there are security issues in the RTL.
    If there are no falsified assertions in the output from the assertion checker tool, that means there are no verified security issues in the RTL.

    """

    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = assertions_checker_graph.invoke({"messages": message})
    # log the run
    with open('assertions_checker_agent_run.log', 'a') as log:
        log.write(f"Design filepath: {design_filepath}\n")
        log.write(f"Top module: {top_module}\n")
        log.write(f"Security objective: {security_objective}\n")
        log.write(f"Instruction: {instruction}\n")
        log.write(f"Result:\n")
        for m in result['messages']:
            log.write(m.pretty_repr())
        log.write("\n\n")

    return result['messages'][-1].content

####################################################################################################
# ------------------------------------------ Test ------------------------------------------------ #
####################################################################################################
if AGENT == "assertion":
    log_full_conv_message(f"Running assertions checker agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_assertions_checker_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    #run_assertions_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)


#################################################################################
# ----------------------------- Similar Bug Agent ----------------------------- #
#################################################################################
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

####################################################################################################
# ------------------------------------------ Test ------------------------------------------------ #
####################################################################################################
if AGENT == "similar_bug":
    log_full_conv_message(f"Running similar bug agent on {DESIGN_FILE} for bug: {BUG}")
    run_similar_bug_agent.invoke({"bug": BUG, "file_path": DESIGN_FILE})
    #run_similar_bug_agent(DESIGN_FILE, BUG)

################################################################################
# ------------------------------ LLM CWE Agent ------------------------------- #
################################################################################
@tool
def llm_cwe_details_retriever_tool(security_issue: str):
    """Use this tool to obtain relevant CWE and corresponding details based on the security issue being analyzed."""
    # log things
    log_action_message(f"Running llm cwe details retriever tool on {security_issue}")
    # dataframe with details of cwes
    df_cwes_details = pd.read_csv('cwe_descriptions_and_examples.csv')
    df_cwes_details = df_cwes_details.fillna('')

    ''' Retriever to obtain cwe descriptions '''
    cwe_description_filename = 'cwes_descriptions.txt'
    documents = [Document(page_content=open(cwe_description_filename,'r').read()) ]
    text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
        separators=['=================================='],
        chunk_size=50,
        chunk_overlap=0,
    )
    doc_splits = text_splitter.split_documents(documents)
    # Add to vectorDB
    vectorstore = InMemoryVectorStore.from_documents(
        documents=doc_splits,
        collection_name="cwe-descriptions",
        embedding=OpenAIEmbeddings(),
    )
    cwe_description_retriever = vectorstore.as_retriever(search_kwargs={"k": 1})

    cwe_details = ""
    try:
        output = cwe_description_retriever.invoke(security_issue)
        match = re.search(r"CWE-\d+:.+",output[0].page_content)
        r = df_cwes_details[df_cwes_details['name']==match.group(0)]
        cwe_details = '\n'.join(r.values[0])
    except BaseException as e:
        return f"Failed to execute. Error: {repr(e)}\n{error_string(e)}"
    
    output = f"Successfully executed:\n```LLM CWE details retriever tool\n```\nOutput:\n {cwe_details}"

    return output

def build_llm_cwe_checker_graph():
    ''' Agent for LLM CWE Checker '''
    if MODEL == "openai":
        llm = ChatOpenAI(model="gpt-4.1-mini")
    elif MODEL == "sonnet":
        llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    else:
        llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    llm_cwe_checker_tools = [llm_cwe_details_retriever_tool]
    llm_cwe_checker = llm.bind_tools(llm_cwe_checker_tools)

    # Nodes of graph
    sys_msg_llm_cwe_checker_agent = SystemMessage(content="You are a helpful assistant tasked with testing RTL code for security issues using guidance from Common Weakness Enumerations (CWEs).")
    def llm_cwe_checker_agent(state: MessagesState):
        return {"messages": [llm_cwe_checker.invoke([sys_msg_llm_cwe_checker_agent] + state["messages"])]}

    def llm_cwe_tools_condition(state) -> Literal["llm_cwe_checker_tools", "END"]:
        
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        
        if len(state["messages"]) > 6:
            return "END"
        elif isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "llm_cwe_checker_tools"
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("llm_cwe_checker_agent", llm_cwe_checker_agent)
    builder.add_node("llm_cwe_checker_tools", ToolNode(llm_cwe_checker_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "llm_cwe_checker_agent")
    builder.add_conditional_edges(
        "llm_cwe_checker_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        llm_cwe_tools_condition,
        {"llm_cwe_checker_tools":"llm_cwe_checker_tools", "END":END},
    )
    builder.add_edge("llm_cwe_checker_tools", "llm_cwe_checker_agent")

    llm_cwe_checker_graph = builder.compile()

    return llm_cwe_checker_graph

llm_cwe_checker_graph = build_llm_cwe_checker_graph()

@tool
def run_llm_cwe_checker_agent(
    design_filepath: Annotated[str, "Path to the RTL file"],
    top_module: Annotated[str, "Top module name"],
    security_objective: Annotated[str, "Security objective to check for"],
) -> str:
    """This tool identifies relevant CWE and analyze the RTL code to find relevant bugs."""
    #print(f"Running llm cwe checker agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    log_action_message(f"Running llm cwe checker agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    update_budget('run_llm_cwe_checker_agent')
    # check if file exists
    if not os.path.exists(design_filepath):
        return "File does not exist."
    file_content = open(design_filepath, 'r').read()

    # Create the instruction for the assertions checker agent
    instruction = f"""Are there security concerns related to {security_objective} in the provided RTL:
    \"\"\"

    {file_content}

    \"\"\"


    Identify the CWE relevant to the security issue for the given RTL.
    Obtain details of the CWE.

    Then determine if there are security issues relevant to the identified CWE in the RTL.
    Refer to the code that corresponds to the issues identified.
    """

    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = llm_cwe_checker_graph.invoke({"messages": message})
    
    return result['messages'][-1].content

####################################################################################################
# ------------------------------------------ Test ------------------------------------------------ #
####################################################################################################
if AGENT == "cwe":
    log_full_conv_message(f"Running llm cwe checker agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_llm_cwe_checker_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    #run_llm_cwe_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)


####################################################################################################
# -------------------------------------- Anomaly Agent ------------------------------------------- #
####################################################################################################
# XXXX
def get_embedding(input: str, model="text-embedding-3-small"):
    ''' get embedding vector of input string using specified OpenAI embedding model '''
    processed_input = str(input)
    if processed_input.strip():
        resp = client.embeddings.create(input=[processed_input], model=model)
        return resp.data[0].embedding
    else:
        return None


def cluster(df):
    # Convert column to NumPy array
    X = np.array(df["embedding"].tolist())
    # print(X)
    # Apply DBSCAN clustering
    dbscan = DBSCAN(eps=0.3, min_samples=2, metric='cosine')  # Use 'cosine' for text embeddings
    labels = dbscan.fit_predict(X)

    # Add results back to DataFrame
    df["cluster"] = labels


def extractAssigns(text):
    assigns = []
    for line in text.split('\n'):
        if line.strip().startswith('assign'):
            assigns.append(line.strip())
    return assigns

@tool
def anomaly_detector_tool(design_filepath: str):

    """Use this tool to identify anomalous code in RTL through forming clusters."""
    similar_constructs_details = "Here are clusters of similar verilog constructs in the RTL file:\n\n"
    try:
        with open(design_filepath, "r") as to_analyze:
            text = to_analyze.read()

        constructs = extractAssigns(text)
        # print(f"got {len(constructs)} contAssigns")

        df = pd.DataFrame({'construct': constructs})
        df["embedding"] = df['construct'].apply(get_embedding)

        cluster(df)
        df = df[df["cluster"] != -1]
        # print(df)

        for cluster_id in set(df["cluster"]):
            # print("Cluster", cluster_id)
            similar_constructs_details += "\n\nCluster " + str(cluster_id)+':\n'
            for construct in df[df["cluster"] == cluster_id]["construct"]:
                similar_constructs_details += f"{str(construct)}\n"

            # print(similar_constructs_details)
        
    except BaseException as e:
        return f"Failed to execute. Error: {repr(e)}"
    
    output = f"Successfully executed:\n```LLM Anomaly Detector tool\n```\nOutput:\n{similar_constructs_details}"

    return output

def build_llm_anomaly_detector_graph():
    ''' Agent for LLM guided anomaly detection '''
    llm = ChatOpenAI(model="gpt-4.1-mini")
    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="gpt-4.1-mini")
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)    
    
    llm_anomaly_detection_tools = [anomaly_detector_tool]
    llm_anomaly_detector = llm.bind_tools(llm_anomaly_detection_tools, parallel_tool_calls=False)

    # Nodes of graph
    sys_msg_llm_anomaly_detector_agent = SystemMessage(content="You are a helpful assistant tasked with testing RTL code for security issues using anomaly detection. The anomaly detection tool clusters similar line of code in the design. From the clusters, identify anomalies and determine if they are security issues.")
    def llm_anomaly_detector_agent(state: MessagesState):
        return {"messages": [llm_anomaly_detector.invoke([sys_msg_llm_anomaly_detector_agent] + state["messages"])]}

    def llm_anomaly_detector_condition(state) -> Literal["llm_anomaly_detection_tools", "END"]:
        
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        if len(state["messages"]) > 6:
            return "END"
        elif isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "llm_anomaly_detection_tools"
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("llm_anomaly_detector_agent", llm_anomaly_detector_agent)
    builder.add_node("llm_anomaly_detection_tools", ToolNode(llm_anomaly_detection_tools))

    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "llm_anomaly_detector_agent")
    builder.add_conditional_edges(
        "llm_anomaly_detector_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        llm_anomaly_detector_condition,
        {"llm_anomaly_detection_tools":"llm_anomaly_detection_tools", "END":END},
    )
    builder.add_edge("llm_anomaly_detection_tools", "llm_anomaly_detector_agent")

    llm_anomaly_detector_graph = builder.compile()

    return llm_anomaly_detector_graph

llm_anomaly_detector_graph = build_llm_anomaly_detector_graph()
client = OpenAI()

@tool
def run_anomaly_detector_agent(
    design_filepath: Annotated[str, "Path to the RTL file"],
    top_module: Annotated[str, "Top module name"],
    security_objective: Annotated[str, "Security objective to check for"],
) -> str:
    """Use this tool to run the anomaly detector agent on the given RTL code.
    The anomaly agent identifies repeated patterns in the RTL code and clusters them. 
    Then identifies outliers in the cluster as possible anomalies."""

    print(f"Running anomaly detector agent on {design_filepath} for {top_module} with security objective: {security_objective}")
    # check if file exists
    if not os.path.exists(design_filepath):
        return "File does not exist."
    file_content = open(design_filepath, 'r').read()

    # Create the instruction for the assertions checker agent
    instruction = f"""Are there security concerns related to {security_objective} in the provided RTL:
    The design filepath is:

    {design_filepath}

    The RTL code is:
    '''verilog
    {file_content}
    '''

    Use the anomaly detector tool to identify lines in the design RTL that are anomalous.
    Then determine whether the identified anomalous line(s) represent a security issue or not.

    """

    # Create the message for the agent
    message = [HumanMessage(content=instruction)]
    # Run the agent
    result = llm_anomaly_detector_graph.invoke({"messages": message})
    
    return result['messages'][-1].content

####################################################################################################
# ------------------------------------------ Test ------------------------------------------------ #
####################################################################################################
if AGENT == "anomaly":
    log_full_conv_message(f"Running llm cwe checker agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_anomaly_detector_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    #run_llm_cwe_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)


    
####################################################################################################
# ------------------------------------- Final Review Agent --------------------------------------- #
####################################################################################################
# This agent is used to review the final report and polish the summary of the security analysis.
def build_review_graph():
    ''' Agent for review the final report and polish the summary of the security analysis '''
    if MODEL == "openai":
        llm = ChatOpenAI(model="o4-mini")
    elif MODEL == "sonnet":
        llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    else:
        llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    review_tools = [list_dir, read_file, read_file_with_line_numbers, llm_cwe_details_retriever_tool]
    review = llm.bind_tools(review_tools)

    # Nodes of graph
    sys_msg_review_agent = SystemMessage(content=(
    "You are a hardware security expert tasked with reviewing and refining the final security analysis report before it is delivered to the client. "
    "Verify each claimed security issue: if valid, check the reported bug location and revise the report accordingly. "
    "The reported bug location might not be accurate. If not accurate, idewntify the correct location and update the report. "
    "Ensure the final report includes a clear explanation of each bug, the relevant buggy code, the precise location of the issue, and the tools used to identify it."))

    def review_agent(state: MessagesState):
        return {"messages": [review.invoke([sys_msg_review_agent] + state["messages"])]}

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

review_graph = build_review_graph()


if AGENT == "agentic":
#################################################################################################
# --------------------------------------- Agentic Graph --------------------------------------- #
#################################################################################################
    llm = ChatOpenAI(model="gpt-4.1", temperature=0.14)
    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="gpt-4.1", temperature=0.14)
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    security_analysis_tools = [run_anomaly_detector_agent, run_verilator_agent, run_llm_cwe_checker_agent, run_assertions_checker_agent, run_linter_agent, run_similar_bug_agent, list_dir, read_file, read_file_with_line_numbers]
    tools = ["run_anomaly_detector_agent", "run_verilator_agent", "run_llm_cwe_checker_agent", "run_assertions_checker_agent", "run_linter_agent", "run_similar_bug_agent", "list_dir", "read_file", "read_file_with_line_numbers"]
    llm_security = llm.bind_tools(security_analysis_tools, parallel_tool_calls=False)

    class MessagesState(MessagesState):
        # Add any keys needed beyond messages, which is pre-built 
        pass

    # Nodes of graph
    #The verilator tests tool allows to run the verilator tests on the given IP. Tests passing do not necessarily rule outr security issues. Failing tests might contain relevant information to identify security issues.
    sys_msg = SystemMessage(content=f"""
    You are a supervisor agent in a multi-agent system focused on identifying hardware security vulnerabilities in RTL code. 
    Your objective is to analyze the given SoC and generate a detailed security report.

    You have access to the following tools: {tools}. Each tool specializes in a specific task:

    - Verilator Agent: Runs Verilator tests on the given IP and analyzes failing test reports to detect potential security issues.
    - Assertion Agent: Takes a Verilog file, a top module name, and a security aspect to check. It generates and runs security assertions on the RTL. Failing assertions indicate potential issues that require further localization.
    - Linter Agent: Accepts a Verilog file, top module, and security focus. It selects relevant lint checks and flags design violations tied to security concerns.
    - CWE Agent: Given a Verilog file, a top module, and a security aspect, this agent maps the RTL code to relevant CWEs and detects CWE-related vulnerabilities.
    - Similar Bug Agent: Accepts a file path and a line number (where a bug was found) to locate similar patterns or recurring bugs throughout the RTL code.

    Instructions for analysis:

    - Read the documentataion to identify security features and register interfaces policies.
    - Use Verilator, Assertion, Anomaly and Linter agents to uncover initial issues in the design.
    - If a bug is detected but not localized, use the CWE Agent to further inspect the related security aspect in the surrounding RTL.
    - After detecting any bugs, use the Similar Bug Agent to scan similar files (of the same or of different IPs) for similar vulnerabilities.

    Output Format:

    - For each identified issue, report:
    - File name
    - Line number(s)
    - Brief description of the issue
    - Security aspect affected
    - Tools used to identify the issue

    When your analysis is complete, end your response with "END".
    """)
    def security_agent(state: MessagesState):
        return {"messages": [llm_security.invoke([sys_msg] + state["messages"])]}

    def final_report_node(state: MessagesState):
        final_instruction = HumanMessage(
            content=(
                "The resource budget has been exhausted. Please summarize the security analysis so far, "
                "highlighting any findings or observations made during the previous steps."
            )
        )
        summary_message = llm_security.invoke( state["messages"] + [final_instruction])
        log_full_conv_message(final_instruction.pretty_repr())
        log_full_conv_message(summary_message.pretty_repr())
        log_main_conv_message(final_instruction.pretty_repr())
        log_main_conv_message(summary_message.pretty_repr())
        return {"messages": [summary_message]}

    def tools_condition(state) -> Literal["security_tools", "final_report", "review"]:
        
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        log_main_conv_message(prev_message.pretty_repr())
        log_main_conv_message(last_message.pretty_repr())
        if is_budget_exceeded():
            return "final_report"
        if isinstance(last_message, AIMessage) and last_message.tool_calls:

            return "security_tools"
        
        log_action_message(f"Review Agent invoked")
        return "END"

    # Graph
    builder = StateGraph(MessagesState)

    # Define nodes: these do the work
    builder.add_node("security_agent", security_agent)
    builder.add_node("security_tools", ToolNode(security_analysis_tools))
    builder.add_node("final_report", final_report_node)
    builder.add_node("review", review_graph)
    # Define edges: these determine how the control flow moves
    builder.add_edge(START, "security_agent")
    builder.add_conditional_edges(
        "security_agent",
    #     If the latest message (result) from assistant is a tool call -> tools_condition routes to tools
    #     If the latest message (result) from assistant is a not a tool call -> tools_condition routes to END
        tools_condition,
        #{"security_tools":"security_tools","final_report": "final_report", "review":"review"},
        {"security_tools":"security_tools","final_report": "final_report", "END":END},
    )
    builder.add_edge("security_tools", "security_agent")
    builder.add_edge("final_report", END)
    #builder.add_edge("review", END)

    ####################################################################################################
    # ------------------------------------------ Test ------------------------------------------------ #
    ####################################################################################################
    security_graph = builder.compile()

    # test agent
    instruction = f"""Identify security issues in the {IP_STRING} OpenTitan SoC, located at {SOC_BASE_DIR}.

    - All IPs are located in the 'hw/ip' directory.
    - RTL code for each IP is located in its 'rtl' subdirectory, with source files having the '.sv' extension.
        - reg_top files contain the register interface for the IP.
        - control/fsm files contain the control logic for the IP.
        - core files contain the core logic for the IP.
    - Documentation files (.md) are located in the 'doc' directories of each IP.
        - theory_of_operation explains the properties of the IP and its security features.
        - registers.md files contain the register interface and its read/write access policies.
    - Ignore '.core' files; they are used by build tools and are not relevant for security analysis.

    {FOCUS_STRING}

    First, identify the relevant security properties and read/write policies of the register interfaces from the documentation. 
    Then, use all available tools to perform a comprehensive security analysis on the RTL code.
    """


    message = [HumanMessage(content=instruction)]

    log_full_conv_message(sys_msg.pretty_repr())
    log_main_conv_message(sys_msg.pretty_repr())

    # for m in security_graph.stream({"messages": message}, subgraphs=True):
    #     print(m)
    #     print("----")
    result = security_graph.invoke({"messages": message}, {"recursion_limit": 1000})
    for m in result['messages']:
        m.pretty_print()

    # m = run_linter_agent("/home/XXXX-2/hackdate/hw/ip/aes/rtl/aes_cipher_core.sv","aes_cipher_core","FSM")
    # print(m)