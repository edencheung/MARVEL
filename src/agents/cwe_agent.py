import os
import re

from typing import Annotated, Literal

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_deepseek import ChatDeepSeek

from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState, END

from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_text_splitters import RecursiveCharacterTextSplitter


from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from typing import Annotated

from langgraph.graph import MessagesState

from langgraph.prebuilt import ToolNode
import pandas as pd

from settings import *
from utils.budget import update_budget
from utils.logging import error_string, log_action_message, log_full_conv_message

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