from utils.logging import log_action_message


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