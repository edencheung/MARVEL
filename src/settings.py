import argparse


SOC_BASE_DIR = "/home/eden/Desktop/Code/HACK@CHES/p2/opentitan"

# # IP to analyze. If not specified analyzes whole SOC
# IP = 'all'

# # "openai", "deepseek", "sonnet"
# MODEL = 'openai'

# # Can be verilator - assertions - linter - agentic - cwe - similar_bug
# AGENT = 'agentic'

# # Top module name. Required for assertions, linter, and cwe agents
# TOP_MODULE = ""

# # Design file to analyze. Required for assertions, linter, similar bug and cwe agents
# DESIGN_FILE = ""

# # Security objective to check for. Required for assertions, linter and cwe agents
# SECURITY_OBJECTIVE = ""

# # Bug example to check for. Required for similar bug agent
# BUG = ""

# # Temperature for the model. Default is 0.2
# TEMP = 0.2

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