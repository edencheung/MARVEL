import os
import re
import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
from pathlib import Path
import pandas as pd
import numpy as np
LOG_DIR = "agentic"  # change this to your logs folder

# regex patterns
action_patterns = {
    'list dir': r'Listing directory: (.+)',
    'read file': r'Reading file(?: with line numbers)?: (.+)',
    'run_agent': r'Running (.+ agent) on (.+?)(?: for (\w+) with security objective: (.+))?$',
    #'run_tool': r'Running (\w+ tool) on (.+)',
    #'run_lint_agent': r'Running lint checker tool on (.+?) for (\w+) with lint tags: (.+)',
}

def smart_capitalize(agent_name):
    if "llm" in agent_name:
        agent_name = agent_name.replace("llm", "LLM")
    return ' '.join([w if w.isupper() else w.capitalize() for w in agent_name.split()])


# parsing function
def parse_log(file_path):
    full_name = Path(file_path).stem
    design_name = full_name.split("_sonnet_")[0]  # extract just the design name    results = []
    results = []

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            for action, pattern in action_patterns.items():
                match = re.search(pattern, line)
                if match:
                    entry = {'action': action, 'design': design_name}
                    if action == 'list dir' or action == 'read file':
                        entry['file'] = match.group(1)
                    elif action == 'run_agent':
                        full_action = smart_capitalize(match.group(1))
                        print(f"Full action: {full_action}")
                        entry['action'] = full_action
                        entry.update({
                            'file': match.group(2),
                            'module': match.group(3),
                            'objective': match.group(4)
                        })
                    elif action == 'run_tool':
                        entry.update({
                            'tool': match.group(1),
                            'objective': match.group(2)
                        })
                    elif action == 'run_lint_agent':
                        entry.update({
                            'file': match.group(1),
                            'module': match.group(2),
                            'tags': eval(match.group(3))  # Be careful with eval in prod
                        })
                    print(f"Parsed entry: {entry}")
                    results.append(entry)
                    break
    return results

# process all logs
def process_all_logs(log_dir):
    all_data = []
    for log_file in os.listdir(log_dir):
        if log_file.endswith("actions_log.txt"):
            log_path = os.path.join(log_dir, log_file)
            all_data.extend(parse_log(log_path))
    return all_data

def plot_normalized_action_distribution_by_design(data, output_file="normalized_action_distribution.pdf"):
    from collections import defaultdict
    import matplotlib.cm as cm

    # 1. Collect action counts per design
    design_action_counts = defaultdict(Counter)
    for entry in data:
        design = entry['design']
        action = entry['action']
        design_action_counts[design][action] += 1

    # 2. Add agglomerated data under key "All"
    all_actions = Counter([entry['action'] for entry in data])
    design_action_counts["Overall"] = all_actions

    # 3. Extract all unique actions
    all_actions_set = set()
    for action_counts in design_action_counts.values():
        all_actions_set.update(action_counts.keys())
    all_actions_list = sorted(all_actions_set)
    print(f"All actions: {all_actions_list}")
    # 4. Normalize to percentage
    normalized = {}
    for design, action_counts in design_action_counts.items():
        total = sum(action_counts.values())
        normalized[design] = {action: (action_counts.get(action, 0) / total) * 100 for action in all_actions_list}

    # 5. Create DataFrame for plotting
    df = pd.DataFrame.from_dict(normalized, orient='index')[all_actions_list]
    df = df.fillna(0)
    df = df.sort_index()

    # 6. Plot
    sns.set_theme(style="whitegrid", font_scale=1.5)
    plt.figure(figsize=(16,5))
    bottom = np.zeros(len(df))
    colors = sns.color_palette("Set2", n_colors=len(all_actions_list))

    for idx, action in enumerate(all_actions_list):
        values = df[action].values
        plt.bar(df.index, values, bottom=bottom, label=action, color=colors[idx])
        bottom += values

    # plt.xticks(rotation=20, ha='center')
    plt.ylabel("Percentage")
    # plt.title("Normalized Action Distribution by Design")
    handles, labels = plt.gca().get_legend_handles_labels()
    ncol = len(labels)/2
    plt.legend(handles, labels, title="Action", bbox_to_anchor=(0.5, 1.4), loc='upper center', ncol=ncol)
    plt.tight_layout(rect=[0, 0, 1, 1])  # Leave space for the top legend
    plt.savefig(output_file, format='pdf')
    plt.close()


def get_file_extension(file_path):
    return Path(file_path).suffix if file_path else "none"

def prepare_running_actions_df(data):
    filtered = [entry for entry in data if entry['action'].startswith('run_')]
    records = []
    for entry in filtered:
        action = entry['action']
        objective = entry.get('objective', 'none')
        file_type = get_file_extension(entry.get('file', ''))

        records.append({
            'action': action,
            'objective': objective,
            'file_type': file_type
        })

    df = pd.DataFrame(records)
    return df

def plot_action_vs_objective_vs_filetype(df, output_file="action_obj_filetype.pdf"):
    plt.figure(figsize=(10, 6))
    sns.set(style="whitegrid", font_scale=1.3)

    grouped = df.groupby(['action', 'objective', 'file_type']).size().reset_index(name='count')

    sns.scatterplot(
        data=grouped,
        x='action',
        y='objective',
        hue='file_type',
        size='count',
        sizes=(50, 500),
        palette='deep',
        edgecolor='black',
        linewidth=0.5
    )

    plt.title("Action vs Security Objective vs File Type", fontsize=14)
    plt.xlabel("Action Type")
    plt.ylabel("Security Objective")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', borderaxespad=0.)
    plt.savefig(output_file, format='pdf')
    plt.close()

if __name__ == "__main__":
    all_data = process_all_logs(LOG_DIR)

    # Save overall action distribution
    plot_normalized_action_distribution_by_design(all_data)

    # Save NeurIPS-quality plot of action vs objective vs file type
    df_running = prepare_running_actions_df(all_data)
    #plot_action_vs_objective_vs_filetype(df_running, output_file="action_objective_filetype.pdf")
