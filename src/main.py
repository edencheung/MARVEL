from dotenv import load_dotenv

load_dotenv()


from typing import Literal

from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState, END
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import MessagesState
from langgraph.prebuilt import tools_condition
from langgraph.prebuilt import ToolNode

from settings import *

from utils.logging import log_full_conv_message, log_main_conv_message, log_action_message, log_token_usage, log_final_token_summary
from utils.budget import is_budget_exceeded
from utils.file_tools import read_file_with_line_numbers, list_dir, read_file
from utils.rate_limit_handler import safe_llm_call
from utils.token_tracker import token_tracker

from agents.lint_agent import run_linter_agent
from agents.verilator_agent import run_verilator_agent
from agents.assertion_agent import run_assertions_checker_agent
from agents.similar_bug_agent import run_similar_bug_agent
from agents.cwe_agent import run_llm_cwe_checker_agent
from agents.anomaly_agent import run_anomaly_detector_agent
from agents.review_agent import build_review_graph

class MessagesState(MessagesState):
    # Add any keys needed beyond messages, which is pre-built 
    pass


if IP == "all":
    IP_STRING = "whole"
    FOCUS_STRING = "Make sure to analyze the whole SOC and not just some IPs. You can find higher level documentation in hw/doc to understand the whole SOC."
else:
    IP_STRING = f"{IP} IP of the"
    FOCUS_STRING = f"Focus on the {IP} IP and make sure to analyze it thoroughly."

###############
# Linter test #
###############

if AGENT == "linter":
    token_tracker.reset()
    log_full_conv_message(f"Running linter agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_linter_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    log_final_token_summary()
    #run_linter_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)

########################
# Verilator agent test #
########################

if AGENT == "verilator":
    token_tracker.reset()
    log_full_conv_message(f"Running verilator agent on {IP}")
    run_verilator_agent.invoke({"ip": IP})
    log_final_token_summary()

########################
# Assertion agent test #
########################

if AGENT == "assertion":
    token_tracker.reset()
    log_full_conv_message(f"Running assertions checker agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_assertions_checker_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    log_final_token_summary()
    #run_assertions_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)

##########################
# Similar bug agent test #
##########################

if AGENT == "similar_bug":
    token_tracker.reset()
    log_full_conv_message(f"Running similar bug agent on {DESIGN_FILE} for bug: {BUG}")
    run_similar_bug_agent.invoke({"bug": BUG, "file_path": DESIGN_FILE})
    log_final_token_summary()
    #run_similar_bug_agent(DESIGN_FILE, BUG)

######################
# LLM CWE agent test #
######################

if AGENT == "cwe":
    token_tracker.reset()
    log_full_conv_message(f"Running llm cwe checker agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_llm_cwe_checker_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    log_final_token_summary()
    #run_llm_cwe_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)

######################
# Anomaly agent test #
######################

if AGENT == "anomaly":
    token_tracker.reset()
    log_full_conv_message(f"Running anomaly detector agent on {DESIGN_FILE} for {TOP_MODULE} with security objective: {SECURITY_OBJECTIVE}")
    run_anomaly_detector_agent.invoke({"design_filepath": DESIGN_FILE, "top_module": TOP_MODULE, "security_objective": SECURITY_OBJECTIVE})
    log_final_token_summary()
    #run_llm_cwe_checker_agent(DESIGN_FILE, TOP_MODULE, SECURITY_OBJECTIVE)

#################################################################################################
# --------------------------------------- Agentic Graph --------------------------------------- #
#################################################################################################
review_graph = build_review_graph()

if AGENT == "agentic":
    # Initialize token tracking
    token_tracker.reset()
    log_action_message("Token tracking initialized for agentic analysis")
    
    llm = ChatOpenAI(model="gpt-5", temperature=0.14)
    # if MODEL == "openai":
    #     llm = ChatOpenAI(model="gpt-4.1", temperature=0.14)
    # elif MODEL == "sonnet":
    #     llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=TEMP)
    # else:
    #     llm = ChatDeepSeek(model="deepseek-chat", temperature=TEMP)

    # security_analysis_tools = [run_anomaly_detector_agent, run_verilator_agent, run_llm_cwe_checker_agent, run_assertions_checker_agent, run_linter_agent, run_similar_bug_agent, list_dir, read_file, read_file_with_line_numbers]
    # tools = ["run_anomaly_detector_agent", "run_verilator_agent", "run_llm_cwe_checker_agent", "run_assertions_checker_agent", "run_linter_agent", "run_similar_bug_agent", "list_dir", "read_file", "read_file_with_line_numbers"]
    security_analysis_tools = [run_anomaly_detector_agent, run_llm_cwe_checker_agent, run_similar_bug_agent, list_dir, read_file, read_file_with_line_numbers]
    tools = ["run_anomaly_detector_agent", "run_llm_cwe_checker_agent", "run_similar_bug_agent", "list_dir", "read_file", "read_file_with_line_numbers"]
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

    - CWE Agent: Given a Verilog file, a top module, and a security aspect, this agent maps the RTL code to relevant CWEs and detects CWE-related vulnerabilities.
    - Similar Bug Agent: Accepts a file path and a line number (where a bug was found) to locate similar patterns or recurring bugs throughout the RTL code.

    Instructions for analysis:

    - Read the documentataion to identify security features and register interfaces policies.
    - Read through the different systemverilog files to probe for issues and use the anomaly agent
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
        return {"messages": [safe_llm_call(llm_security.invoke, [sys_msg] + state["messages"])]}

    def final_report_node(state: MessagesState):
        final_instruction = HumanMessage(
            content=(
                "The resource budget has been exhausted. Please summarize the security analysis so far, "
                "highlighting any findings or observations made during the previous steps."
            )
        )
        summary_message = safe_llm_call(llm_security.invoke, state["messages"] + [final_instruction])
        log_full_conv_message(final_instruction.pretty_repr())
        log_full_conv_message(summary_message.pretty_repr())
        log_main_conv_message(final_instruction.pretty_repr())
        log_main_conv_message(summary_message.pretty_repr())
        
        # Log final token usage summary
        log_final_token_summary()
        
        return {"messages": [summary_message]}

    def tools_condition(state) -> Literal["security_tools", "final_report", "review"]:
        
        prev_message = state["messages"][-2]
        last_message = state["messages"][-1]
        log_full_conv_message(prev_message.pretty_repr())
        log_full_conv_message(last_message.pretty_repr())
        log_main_conv_message(prev_message.pretty_repr())
        log_main_conv_message(last_message.pretty_repr())
        
        # Log current token usage
        # log_token_usage()
        
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

    # Log final comprehensive token usage summary
    log_action_message("Agentic analysis completed")
    log_final_token_summary()
    
    # Print token summary to console as well
    print("\n" + "="*60)
    print("FINAL TOKEN USAGE SUMMARY")
    print("="*60)
    print(token_tracker.get_formatted_summary())
    print("="*60)

    # m = run_linter_agent("/home/XXXX-2/hackdate/hw/ip/aes/rtl/aes_cipher_core.sv","aes_cipher_core","FSM")
    # print(m)