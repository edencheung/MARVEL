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
from agents.lint_agent import gen_opentitan_filelist
from utils.budget import update_budget
from utils.logging import error_string, log_action_message, log_full_conv_message
from utils.rate_limit_handler import safe_llm_call

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
        return {"messages": [safe_llm_call(llm_assertion_checker.invoke, [sys_msg_assertion_checker_agent] + state["messages"])]}

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
    result = assertions_checker_graph.invoke({"messages": message}, {"recursion_limit": 200})
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