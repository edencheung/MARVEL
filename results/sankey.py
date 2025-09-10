import os
from collections import defaultdict
import plotly.graph_objects as go

# === Configuration ===
log_dir = "agentic"  # directory with all logs
log_postfix = "_actions_log.txt"  # only files with this postfix are parsed

# === Step 1: Extract actions from logs ===
def parse_log_file(filepath):
    actions = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Running"):
                action = line.split(" ", 2)[1]  # e.g., 'verilator', 'linter', etc.
                actions.append(action)
            elif line.startswith("Reading file"):
                actions.append("read_file")
            elif line.startswith("Reading file with line numbers"):
                actions.append("read_file_numbered")
            elif line.startswith("Listing directory"):
                actions.append("list_dir")
    return actions

# === Step 2: Count transitions ===
transition_counts = defaultdict(int)
all_actions = set()

for filename in os.listdir(log_dir):
    if filename.endswith(log_postfix):
        filepath = os.path.join(log_dir, filename)
        actions = parse_log_file(filepath)
        for i in range(len(actions) - 1):
            a, b = actions[i], actions[i+1]
            transition_counts[(a, b)] += 1
            all_actions.update([a, b])

# === Step 3: Build Sankey Diagram Data ===
all_actions = sorted(all_actions)
action_to_index = {action: i for i, action in enumerate(all_actions)}

sources = []
targets = []
values = []

for (src, tgt), count in transition_counts.items():
    sources.append(action_to_index[src])
    targets.append(action_to_index[tgt])
    values.append(count)

# === Step 4: Plot using Plotly ===
fig = go.Figure(data=[go.Sankey(
    node=dict(
        pad=15,
        thickness=20,
        line=dict(color="black", width=0.5),
        label=all_actions,
    ),
    link=dict(
        source=sources,
        target=targets,
        value=values,
    ))])


# Save to file
output_pdf_path = "sankey_agent_transitions.pdf"
fig.write_image(output_pdf_path, format="pdf")
print(f"Saved Sankey diagram to {output_pdf_path}")