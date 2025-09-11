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

from utils.logging import log_full_conv_message
from utils.rate_limit_handler import exponential_backoff_retry, safe_openai_call

@exponential_backoff_retry(max_retries=5, base_delay=1.0)
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
        return {"messages": [safe_openai_call(llm_anomaly_detector.invoke, [sys_msg_llm_anomaly_detector_agent] + state["messages"])]}

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