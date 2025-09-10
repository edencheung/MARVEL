from settings import *
import traceback

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

def error_string(ex: Exception) -> str:
    return '\n'.join([
        ''.join(traceback.format_exception_only(None, ex)).strip(),
        ''.join(traceback.format_exception(None, ex, ex.__traceback__)).strip()
])