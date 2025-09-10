SOC_BASE_DIR = "/home/ubuntu/hackdate"

# IP to analyze. If not specified analyzes whole SOC
IP = 'all'

# "openai", "deepseek", "sonnet"
MODEL = 'openai'

# Can be verilator - assertions - linter - agentic - cwe - similar_bug
AGENT = 'agentic'

# Top module name. Required for assertions, linter, and cwe agents
TOP_MODULE = ""

# Design file to analyze. Required for assertions, linter, similar bug and cwe agents
DESIGN_FILE = ""

# Security objective to check for. Required for assertions, linter and cwe agents
SECURITY_OBJECTIVE = ""

# Bug example to check for. Required for similar bug agent
BUG = ""

# Temperature for the model. Default is 0.2
TEMP = 0.2