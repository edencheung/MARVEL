import re
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm # For colormaps
import numpy as np
import sys # To exit gracefully on errors
# Removed sklearn and openai imports as automatic clustering is replaced by manual mapping

# --- Configuration ---
# Directory containing your log files
log_directory = "./agentic" # <--- CHANGE THIS TO YOUR LOG DIRECTORY
# File postfix to filter log files (e.g., ".log", ".txt")
file_postfix_filter = "actions_log.txt" # <--- CHANGE THIS TO THE POSTFIX OF YOUR LOG FILES

# --- Manual Clustering Definitions ---
# Define your manual security objective clusters
# Key: Original Security Objective String
# Value: Your Manual Cluster Label (Title)
manual_objective_clusters = {
    'state machine security': 'FSM Security',
    'FSM security': 'FSM Security',
    'cryptographic core security': 'FSM Security',
    'FSM': 'FSM Security',
    'deadlock': 'FSM Security',
    'FSM deadlock': 'FSM Security',
    'improper state transitions': 'FSM Security',
    'CWE mapping for state management': 'FSM Security',
    'cryptographic state access control': 'FSM Security',
    'error handling': 'FSM Security',
    'state management': 'FSM Security',
    'cryptographic state update': 'FSM Security',
    'context switching': 'FSM Security',
    'state machine': 'FSM Security',
    'context switching anomalies': 'FSM Security',
    'illegal state transitions': 'FSM Security',
    'FSM stuck/faulty': 'FSM Security',
    'FSM hardening': 'FSM Security',
    'state transition': 'FSM Security',
    'stuck states': 'FSM Security',
    'error state handling': 'FSM Security', 
    'terminal error state enforcement': 'FSM Security', 
    'sparse encoding': 'FSM Security', 

    'register access': 'Access Control',
    'privilege escalation': 'Access Control',
    'reserved bits': 'Access Control',
    'interrupt security': 'Access Control',
    'register access security': 'Access Control',
    'register interface security': 'Access Control',
    'register access policy enforcement': 'Access Control',
    'register access control': 'Access Control',
    'improper access': 'Access Control',
    'key management': 'Access Control',
    'register interface': 'Access Control',
    'access anomalies': 'Access Control',
    'register interface access control': 'Access Control',
    'privilege enforcement': 'Access Control',
    'key register confidentiality': 'Access Control',
    'shadow register': 'Access Control',
    'access policy': 'Access Control',
    'interface security': 'Access Control',
    'register access policy': 'Access Control',
    'shadow register integrity': 'Access Control',
    'shadow register anomalies': 'Access Control',
    'shadowed register integrity': 'Access Control',
    'key handling': 'Access Control',
    'message integrity': 'Access Control',
    'privilege separation': 'Access Control',
    'integrity': 'Access Control',
    'illegal access prevention': 'Access Control',
    'memory integrity': 'Access Control',
    'access control': 'Access Control',
    'direct access interface security': 'Access Control',
    'partition locking': 'Access Control',
    'partition integrity': 'Access Control',
    'partition access control': 'Access Control',
    'life cycle interface access control': 'Access Control',
    'privilege escalation prevention': 'Access Control',
    'integrity error handling': 'Access Control',
    'partition lock enforcement': 'Access Control',
    'protocol compliance': 'Access Control',
    'memory access control': 'Access Control',
    'memory interface security': 'Access Control',
    'entropy integrity': 'Access Control', 
    'register lock': 'Access Control',
    'data path integrity': 'Access Control',

    'entropy': 'Entropy',
    'entropy tracking': 'Entropy',
    'entropy usage': 'Entropy',
    'data leakage': 'Entropy',

    'masking': 'Masking',
    'masking bypass': 'Masking',
    'masking enforcement': 'Masking',
    'FIFO masking': 'Masking',

    'side-channel resistance': 'Side Channels',
    'fault injection resistance': 'Side Channels',
    'fault injection': 'Side Channels',
    'state isolation': 'Side Channels',
    'stuck-at faults': 'Side Channels',
    'application interface isolation': 'Side Channels',
    'clock bypass': 'Side Channels',
    'volatile unlock': 'Side Channels',
    'mutex': 'Side Channels',
    'hardware state machine glitch attack': 'Side Channels',
    'denial of service': 'Side Channels',
    'command sequencing': 'Side Channels',
    'command injection': 'Side Channels',

    'PRNG reseed': 'Other', 
    'reseed counter': 'Other', 
    'reseed counter management': 'Other', 
    'secure wipe': 'Other', 
    'ECC': 'Other', 
    'error propagation': 'Other', 
    'ECC error propagation': 'Other', 
    'token validation': 'Other', 
    'FIFO overflow/underflow': 'Other', 
    # Add any other objectives found in your logs that aren't listed above and assign them to a cluster
    # If an objective is not in this dictionary, it will be assigned 'Unclustered Objective'
}

# Define your manual file postfix clusters
# Key: Original File Postfix String
# Value: Your Manual Cluster Label (Title)
manual_postfix_clusters = {
    'reg_top': 'Interface',
    'core_reg_top': 'Interface',
    'reg_we_check': 'Interface',
    'adapter_reg': 'Interface',
    'adapter_sram': 'Interface',
    'lci': 'Interface',
    'dai': 'Interface',
    'kmac_if': 'Interface',

    'app': 'Core',
    'top': 'Core',
    'core': 'Core',

    'ctrl': 'FSM/Control Logic',
    'controller': 'FSM/Control Logic',
    'fsm': 'FSM/Control Logic',
    'onehot_check': 'FSM/Control Logic',
    'sm': 'FSM/Control Logic',
    'main_sm': 'FSM/Control Logic',
    'cipher_control': 'FSM/Control Logic', # Added based on user request

    'part_buf': 'Other',
    'part_unbuf': 'Other',
    'intr': 'Other',
    'state_db': 'Other',
    'cmd_stage': 'Other',
    'msgfifo': 'Other',
    'prng_masking': 'Other', # Added based on user request
    'ctr_drbg_cmd': 'Other', # Added based on user request
    # Add any other postfixes found in your logs that aren't listed above and assign them to a cluster
    # If a postfix is not in this dictionary, it will be assigned 'Unclustered Postfix'
}


# Regex to capture Agent, File Path, and Security Objective string from relevant lines
log_pattern = re.compile(
    r"^Running (\w+(?: \w+)*) agent on (.+) for .+ with security objective: (.+)$"
)

# Regex to extract the <name> part from the log file name pattern <name>_sonnet_<log_postfix>.txt
log_filename_pattern = re.compile(r"^(.+)_sonnet_.+\.(txt|log)$") # Assuming .txt or .log extension for the log file

# List to store parsed data as dictionaries from all files
all_parsed_data = []

print(f"Starting to process logs from directory: {log_directory}")

# --- File Reading and Parsing ---
if not os.path.isdir(log_directory):
    print(f"Error: Directory not found at {log_directory}")
    sys.exit(1) # Exit the script if the directory doesn't exist

processed_files_count = 0
for root, _, files in os.walk(log_directory):
    for file in files:
        if file.endswith(file_postfix_filter):
            file_path = os.path.join(root, file)
            processed_files_count += 1
            print(f"Processing file: {file_path}")

            # --- Extract <name> from the log file name ---
            name_prefix = None
            log_filename_match = log_filename_pattern.match(file)
            if log_filename_match:
                name_prefix = log_filename_match.group(1)
            else:
                print(f"  Warning: Log file name '{file}' does not match expected pattern <name>_sonnet_<log_postfix>.txt. Cannot extract name prefix for specific postfix extraction.")

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        match = log_pattern.match(line)
                        if match:
                            agent = match.group(1).strip() # Capture agent name
                            log_file_path = match.group(2).strip()
                            security_objective_string = match.group(3).strip()

                            # --- POSTFIX EXTRACTION ---
                            extracted_postfix = None
                            if name_prefix:
                                expected_source_prefix = name_prefix + "_"
                                source_filename = os.path.basename(log_file_path)
                                filename_base, file_extension = os.path.splitext(source_filename)

                                # Ensure filename_base is not empty before searching
                                if filename_base:
                                    prefix_index = filename_base.find(expected_source_prefix)

                                    if prefix_index != -1:
                                        start_index = prefix_index + len(expected_source_prefix)
                                        extracted_postfix = filename_base[start_index:]
                                    else:
                                        last_underscore_index = filename_base.rfind('_')
                                        if last_underscore_index != -1:
                                            extracted_postfix = filename_base[last_underscore_index + 1:]
                                        else:
                                            extracted_postfix = filename_base
                                else:
                                    # Handle empty filename_base
                                    extracted_postfix = ""
                            else:
                                # If name_prefix wasn't found for the log file, fall back to previous logic
                                source_filename = os.path.basename(log_file_path)
                                filename_base, file_extension = os.path.splitext(source_filename)
                                if filename_base:
                                    last_underscore_index = filename_base.rfind('_')
                                    if last_underscore_index != -1:
                                        extracted_postfix = filename_base[last_underscore_index + 1:]
                                    else:
                                        extracted_postfix = filename_base
                                else:
                                    extracted_postfix = ""


                            # Use the extracted postfix, handle empty cases
                            if extracted_postfix:
                                log_file_postfix = extracted_postfix
                            else:
                                log_file_postfix = "unknown" # Assign a placeholder if extraction failed or empty
                            # --- END POSTFIX EXTRACTION ---

                            # Replace "and" with "" before splitting
                            cleaned_objective_string = re.sub(r'\band\b', ',', security_objective_string, flags=re.IGNORECASE)

                            # Split the cleaned security objective string by comma and process each
                            individual_objectives = [obj.strip() for obj in cleaned_objective_string.split(',')]

                            # Add a data entry for each individual objective
                            for objective in individual_objectives:
                                if objective: # Check if the objective string is not empty
                                    # Map original objective and postfix to their manual clusters
                                    objective_cluster = manual_objective_clusters.get(objective, 'Unclustered Objective')
                                    postfix_cluster = manual_postfix_clusters.get(log_file_postfix, 'Unclustered Postfix')

                                    all_parsed_data.append({
                                        'Agent': agent,
                                        'SecurityObjective': objective, # Keep original for reference if needed
                                        'FilePostfix': log_file_postfix, # Keep original for reference if needed
                                        'ObjectiveCluster': objective_cluster, # Use the manual objective cluster
                                        'PostfixCluster': postfix_cluster # Use the manual postfix cluster
                                    })

            except Exception as e:
                print(f"Error reading or parsing file {file_path}: {e}")
                # Continue processing other files

if processed_files_count == 0:
    print(f"No files found with postfix '{file_postfix_filter}' in directory '{log_directory}'")
    sys.exit(1)

print(f"Finished processing {processed_files_count} files.")
print(f"Extracted {len(all_parsed_data)} relevant log entries.")

if not all_parsed_data:
    print("No relevant log entries found matching the pattern. Exiting.")
    sys.exit(0)

# Convert to DataFrame
df = pd.DataFrame(all_parsed_data)

# --- Print Unclustered Objectives ---
print("\n--- Checking for Unclustered Security Objectives ---")
unclustered_objectives_df = df[df['ObjectiveCluster'] == 'Unclustered Objective']
unique_unclustered_objectives = unclustered_objectives_df['SecurityObjective'].unique()

if len(unique_unclustered_objectives) > 0:
    print("Found the following security objectives not assigned to a manual cluster:")
    for obj in unique_unclustered_objectives:
        print(f"- {obj}")
else:
    print("No unclustered security objectives found.")
print("----------------------------------------------------")


# --- Print Unclustered Postfixes ---
print("\n--- Checking for Unclustered File Postfixes ---")
unclustered_postfixes_df = df[df['PostfixCluster'] == 'Unclustered Postfix']
unique_unclustered_postfixes = unclustered_postfixes_df['FilePostfix'].unique()

if len(unique_unclustered_postfixes) > 0:
    print("Found the following file postfixes not assigned to a manual cluster:")
    for post in unique_unclustered_postfixes:
        print(f"- {post}")
else:
    print("No unclustered file postfixes found.")
print("---------------------------------------------")


# --- Group by Manual Clusters and Count Frequencies ---
# Group by Agent, Manual Objective Cluster, and Manual Postfix Cluster
triplet_counts = df.groupby(['Agent', 'ObjectiveCluster', 'PostfixCluster']).size().reset_index(name='Frequency')

print(f"\nFound {len(triplet_counts)} unique Agent-ObjectiveCluster-PostfixCluster triplets based on manual clustering.")

# --- Plotting ---

# Set font sizes for NeurIPS suitability
plt.rcParams.update({'font.size': 10}) # Adjust base font size
plt.rcParams.update({'axes.labelsize': 12})
plt.rcParams.update({'xtick.labelsize': 9})
plt.rcParams.update({'ytick.labelsize': 9})
plt.rcParams.update({'legend.fontsize': 10})
plt.rcParams.update({'figure.titlesize': 14})
plt.rcParams.update({'font.family': 'sans-serif'}) # Use a common sans-serif font
plt.rcParams.update({'font.sans-serif': ['DejaVu Sans', 'Arial']}) # Specify preferred sans-serif fonts

# Get unique categories for axes and colors
# Y-axis: Security Objective Clusters (Manual Titles)
unique_objective_clusters = sorted(df['ObjectiveCluster'].unique())

# Define custom order for Objective Clusters with 'Other' at the top
# Put 'Other' at the end of the list for it to appear at the top of the Y-axis
custom_objective_cluster_order = [cluster for cluster in unique_objective_clusters if cluster != 'Other'] + ['Other']


# X-axis: File Postfix Clusters (Manual Titles)
unique_postfix_clusters_sorted = sorted(df['PostfixCluster'].unique())


# Color: Agents
unique_agents = triplet_counts['Agent'].unique()

# Map agents to colors
if len(unique_agents) > 20:
    print("Warning: More than 20 unique agents. Consider using a different colormap or grouping agents.")
    colors_cmap = plt.colormaps.get_cmap('nipy_spectral')
else:
    colors_cmap = plt.colormaps.get_cmap('tab20' if len(unique_agents) > 10 else 'tab10')

# Now, use the colormap object to get the colors for each agent by index
# Ensure the index is scaled between 0 and 1
agent_color_map = {agent: colors_cmap(i / (len(unique_agents) - 1)) for i, agent in enumerate(unique_agents)}

# --- Deterministic Displacement Mapping ---
# Define base displacement offsets for each agent (unscaled direction)
base_displacement_map = {}
# Example for 4 agents:
if len(unique_agents) >= 1:
    base_displacement_map[unique_agents[0]] = (-1, 1) # Top-Left direction
if len(unique_agents) >= 2:
    base_displacement_map[unique_agents[1]] = (1, 1)  # Top-Right direction
if len(unique_agents) >= 3:
    base_displacement_map[unique_agents[2]] = (-1, -1) # Bottom-Left direction
if len(unique_agents) >= 4:
    base_displacement_map[unique_agents[3]] = (1, -1)  # Bottom-Right direction
# Add more if you have more than 4 unique agents, or group agents if you have many

# Define the maximum displacement magnitudes for the largest bubble
max_horizontal_displacement = 0.25 # Max horizontal displacement for largest bubble
max_vertical_displacement = 0.35 # Max vertical displacement for largest bubble

# Define the minimum scaling factor for displacement (for the smallest bubble)
min_displacement_scale = 0.34 # Smallest bubble will have 30% of max displacement

# We need to map the manual cluster titles to numerical positions for the scatter plot *before* applying displacement
# Use the custom order for objective clusters
objective_cluster_to_pos = {cluster: i for i, cluster in enumerate(custom_objective_cluster_order)} # Use custom order
postfix_cluster_to_pos = {cluster: i for i, cluster in enumerate(unique_postfix_clusters_sorted)} # Use sorted cluster titles

# Use the mapped positions for plotting
triplet_counts['ObjectiveClusterPos'] = triplet_counts['ObjectiveCluster'].map(objective_cluster_to_pos)
triplet_counts['PostfixClusterPos'] = triplet_counts['PostfixCluster'].map(postfix_cluster_to_pos)

# Determine bubble size scaling (needed here to scale displacement)
min_freq = triplet_counts['Frequency'].min()
max_freq = triplet_counts['Frequency'].max()

min_bubble_size = 100 # Consistent with previous step
scale_factor = 1000 # Consistent with previous step

freq_range = max_freq - min_freq
if freq_range == 0:
    triplet_counts['BubbleSize'] = min_bubble_size
    # If all frequencies are the same, displacement scaling factor is max_displacement_scale
    triplet_counts['DisplacementScale'] = 1.0 # Use max scale if all sizes are same
else:
    triplet_counts['BubbleSize'] = triplet_counts['Frequency'].apply(
        lambda freq: min_bubble_size + (freq - min_freq) * (scale_factor - min_bubble_size) / freq_range
    )
    # Calculate a scaling factor for displacement based on BubbleSize
    # Scale BubbleSize from its range [min_bs, max_bs] to the desired displacement scale range [min_displacement_scale, 1.0]
    min_bs = triplet_counts['BubbleSize'].min()
    max_bs = triplet_counts['BubbleSize'].max()
    bs_range = max_bs - min_bs
    if bs_range == 0:
         triplet_counts['DisplacementScale'] = 1.0 # Fallback if all bubble sizes are the same
    else:
        triplet_counts['DisplacementScale'] = triplet_counts['BubbleSize'].apply(
            lambda bs: min_displacement_scale + (bs - min_bs) / bs_range * (1.0 - min_displacement_scale)
        )


# Apply the deterministic displacement, scaled by bubble size
triplet_counts['dx'] = triplet_counts.apply(
    lambda row: base_displacement_map.get(row['Agent'], (0, 0))[0] * max_horizontal_displacement * row['DisplacementScale'],
    axis=1 # Apply the function row-wise
)
triplet_counts['dy'] = triplet_counts.apply(
    lambda row: base_displacement_map.get(row['Agent'], (0, 0))[1] * max_vertical_displacement * row['DisplacementScale'],
    axis=1 # Apply the function row-wise
)


# Calculate the final displaced positions
triplet_counts['PostfixClusterPos_displaced'] = triplet_counts['PostfixClusterPos'] + triplet_counts['dx'] # Postfix Cluster is X
triplet_counts['ObjectiveClusterPos_displaced'] = triplet_counts['ObjectiveClusterPos'] + triplet_counts['dy'] # Objective Cluster is Y

# --- End Deterministic Displacement Mapping ---


# Create the plot
# Adjust figure width based on number of postfix clusters (X), height based on objective clusters (Y)
fig_width = max(8, len(unique_postfix_clusters_sorted) * 1.0) # Adjusted width
fig_height = max(6, len(custom_objective_cluster_order) * 0.8) # Adjusted height based on custom order
fig, ax = plt.subplots(figsize=(fig_width, fig_height))


scatter = ax.scatter(
    x=triplet_counts['PostfixClusterPos_displaced'], # X-axis is Postfix Cluster Position + deterministic displacement
    y=triplet_counts['ObjectiveClusterPos_displaced'],       # Y-axis is Objective Cluster Position + deterministic displacement
    s=triplet_counts['BubbleSize'],
    c=triplet_counts['Agent'].map(agent_color_map),
    alpha=0.7,
    edgecolors='w',
    linewidths=0.5
)

# --- Add Frequency Labels to Bubbles ---
for index, row in triplet_counts.iterrows():
    ax.annotate(
        str(row['Frequency']),  # The text to display (frequency)
        (row['PostfixClusterPos_displaced'], row['ObjectiveClusterPos_displaced']), # Position of the text
        textcoords="offset points", # Offset relative to the point
        xytext=(0,0), # No offset from the point
        ha='center', # Center horizontally
        va='center', # Center vertically
        color='black', # Text color (adjust for visibility)
        fontsize=8 # Text font size (adjust as needed)
    )
# --- End Add Frequency Labels ---


# Set axis ticks and labels using the unique manual cluster titles
# X-axis: File Postfix Clusters
ax.set_xticks(range(len(unique_postfix_clusters_sorted)))
ax.set_xticklabels(unique_postfix_clusters_sorted) # Use sorted cluster titles
# Y-axis: Security Objective Clusters - Use custom order
ax.set_yticks(range(len(custom_objective_cluster_order)))
ax.set_yticklabels(custom_objective_cluster_order) # Use custom order

# Set axis limits to center the ticks and accommodate displacement
# Calculate max possible displacement in each direction for axis limits
# Max displacement is max_displacement_magnitude * max_displacement_scale (which is 1.0)
max_disp_x = max_horizontal_displacement * 1.0
max_disp_y = max_vertical_displacement * 1.0

ax.set_xlim(-0.5 - max_disp_x, len(unique_postfix_clusters_sorted) - 0.5 + max_disp_x)
ax.set_ylim(-0.5 - max_disp_y, len(custom_objective_cluster_order) - 0.5 + max_disp_y) # Adjusted based on custom order


# Add labels
ax.set_xlabel("File Postfix Cluster") # Reverted label
ax.set_ylabel("Security Objective Cluster") # Reverted label
# Removed the plot title

# Add grid lines aligned with ticks
ax.grid(True, linestyle='--', alpha=0.6, which='both')

# Create a legend for agents (colors)
legend_elements = [plt.Line2D([0], [0], marker='o', color='w', label=agent,
                             markerfacecolor=agent_color_map[agent], markersize=10)
                  for agent in unique_agents]

# Position the legend at the top of the plot and arrange in columns
ax.legend(handles=legend_elements, title="Agent", loc='upper center', bbox_to_anchor=(0.5, 1.15),
          ncol=max(1, len(unique_agents) // 2), # Adjust ncol based on number of agents
          fancybox=True, shadow=True)


# Removed the separate legend for bubble size (frequency)

# Adjust layout to make space for the legend at the top
plt.tight_layout(rect=[0, 0, 1, 0.9]) # Adjusted rect to make space at the top

# Save the plot
output_filename = "agent_objective_manual_cluster_postfix_manual_cluster_bubble_grid.pdf" # New filename
plt.savefig(output_filename, format='pdf', bbox_inches='tight')

print(f"Plot saved as {output_filename}")

# Show the plot (optional)
# plt.show()
