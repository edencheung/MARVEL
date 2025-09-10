import os
import subprocess
import stat
from pathlib import Path
import yaml

from typing import Annotated, Literal, List

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from langgraph.graph import StateGraph, START, END
from langgraph.graph import MessagesState, END

import getpass

from langchain_openai import OpenAIEmbeddings
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_text_splitters import RecursiveCharacterTextSplitter, CharacterTextSplitter

from langchain.tools.retriever import create_retriever_tool

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from typing import Annotated

from langgraph.graph import MessagesState

from langgraph.prebuilt import ToolNode

from settings import *
from utils.budget import update_budget
from utils.logging import error_string, log_action_message, log_full_conv_message


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

        tcl_template_file = 'scripts/vcst_template.tcl' 
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