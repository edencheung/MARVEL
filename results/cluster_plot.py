import re
import os
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm # For colormaps
import numpy as np
import sys # To exit gracefully on errors
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics.pairwise import cosine_similarity # Cosine similarity is the metric for clustering
# Import OpenAI library
from openai import OpenAI

# --- Configuration ---
# Directory containing your log files
log_directory = "./agentic" # <--- CHANGE THIS TO YOUR LOG DIRECTORY
# File postfix to filter log files (e.g., ".log", ".txt")
file_postfix_filter = "actions_log.txt" # <--- CHANGE THIS TO THE POSTFIX OF YOUR LOG FILES

# OpenAI API Configuration
# It's recommended to set your API key as an environment variable (e.g., OPENAI_API_KEY)
# If you prefer to hardcode it (NOT RECOMMENDED FOR SECURITY), replace os.environ.get(...)
openai_api_key = os.environ.get("OPENAI_API_KEY")
if not openai_api_key:
    print("Error: OPENAI_API_KEY environment variable not set.")
    print("Please set the OPENAI_API_KEY environment variable with your OpenAI API key.")
    sys.exit(1)

# Initialize OpenAI client
client = OpenAI(api_key=openai_api_key)

# Embedding and Clustering Configuration
# Model to use for generating embeddings (OpenAI model)
embedding_model_name = 'text-embedding-3-large'

# Clustering parameters for Security Objectives
objective_n_clusters = 12

# Clustering parameters for File Postfixes
postfix_n_clusters = 14
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
            log_filename_match = log_filename_pattern.match(file)
            name_prefix = None
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
                                    all_parsed_data.append({
                                        'Agent': agent,
                                        'SecurityObjective': objective, # Use the individual objective
                                        'FilePostfix': log_file_postfix # Use the extracted postfix
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
    print("No relevant log entries found matching the pattern. Extiting.")
    sys.exit(0)

# Convert to DataFrame
df = pd.DataFrame(all_parsed_data)

# --- Clustering Security Objectives ---
print(f"Starting security objective clustering into {objective_n_clusters} clusters using OpenAI embeddings...")

# Get unique security objectives
unique_objectives = df['SecurityObjective'].unique()
print(f"Found {len(unique_objectives)} unique security objectives.")

# Determine the actual number of objective clusters
if len(unique_objectives) < objective_n_clusters:
    print(f"Warning: Number of unique objectives ({len(unique_objectives)}) is less than requested clusters ({objective_n_clusters}). Will use {len(unique_objectives)} clusters.")
    actual_objective_n_clusters = len(unique_objectives)
elif len(unique_objectives) == 0:
    print("No unique objectives found. Skipping objective clustering.")
    actual_objective_n_clusters = 0
else:
    actual_objective_n_clusters = objective_n_clusters

# Perform objective clustering if possible
if actual_objective_n_clusters > 0:
    # Generate embeddings for unique objectives using OpenAI
    print(f"Generating embeddings for {len(unique_objectives)} objectives using OpenAI model: {embedding_model_name}...")
    try:
        response = client.embeddings.create(
            input=list(unique_objectives),
            model=embedding_model_name
        )
        objective_embeddings = np.array([embedding.embedding for embedding in response.data])
        print("Objective embeddings generated.")

        # Perform clustering on objective embeddings
        print(f"Performing Agglomerative Clustering into {actual_objective_n_clusters} clusters...")
        try:
            clustering_obj = AgglomerativeClustering(
                n_clusters=actual_objective_n_clusters,
                metric='cosine',
                linkage='average'
            )
            objective_cluster_labels = clustering_obj.fit_predict(objective_embeddings)
            print(f"Objective clustering complete. Found {len(np.unique(objective_cluster_labels))} clusters.")

            # Create a mapping from original objective to cluster label
            objective_cluster_map = dict(zip(unique_objectives, objective_cluster_labels))

            # Map the cluster labels back to the original DataFrame
            df['ObjectiveCluster'] = df['SecurityObjective'].map(objective_cluster_map)

            # Get unique cluster labels for plotting
            unique_objective_clusters = sorted(df['ObjectiveCluster'].unique())

            # Optional: Print objectives per cluster for inspection
            print("\nObjectives per cluster:")
            for cluster_id in unique_objective_clusters:
                objectives_in_cluster = [obj for obj, label in objective_cluster_map.items() if label == cluster_id]
                print(f"Objective Cluster {cluster_id}: {', '.join(objectives_in_cluster)}")
            print("-" * 20)

        except Exception as e:
            print(f"Error during objective clustering: {e}")
            print("Skipping objective clustering and using original objectives.")
            df['ObjectiveCluster'] = df['SecurityObjective']
            unique_objective_clusters = sorted(df['ObjectiveCluster'].unique()) # Use original objectives
            objective_cluster_map = {obj: obj for obj in unique_objective_clusters} # Map to self

    except Exception as e: # Catch exception from embedding generation
        print(f"Error during objective embedding generation: {e}")
        print("Skipping objective clustering and using original objectives.")
        df['ObjectiveCluster'] = df['SecurityObjective']
        unique_objective_clusters = sorted(df['ObjectiveCluster'].unique()) # Use original objectives
        objective_cluster_map = {obj: obj for obj in unique_objective_clusters} # Map to self

else:
    # Case where actual_objective_n_clusters is 0
    print("Skipping objective clustering due to insufficient unique objectives.")
    df['ObjectiveCluster'] = df['SecurityObjective'] # Use original objectives
    unique_objective_clusters = sorted(df['ObjectiveCluster'].unique()) # Use original objectives
    objective_cluster_map = {obj: obj for obj in unique_objective_clusters} # Map to self


# --- Clustering File Postfixes ---
print(f"\nStarting file postfix clustering into {postfix_n_clusters} clusters using OpenAI embeddings...")

# Get unique file postfixes
unique_postfixes = df['FilePostfix'].unique()
print(f"Found {len(unique_postfixes)} unique file postfixes.")

# Determine the actual number of postfix clusters
if len(unique_postfixes) < postfix_n_clusters:
     print(f"Warning: Number of unique postfixes ({len(unique_postfixes)}) is less than requested clusters ({postfix_n_clusters}). Will use {len(unique_postfixes)} clusters.")
     actual_postfix_n_clusters = len(unique_postfixes)
elif len(unique_postfixes) == 0:
    print("No unique postfixes found. Skipping postfix clustering.")
    actual_postfix_n_clusters = 0
else:
    actual_postfix_n_clusters = postfix_n_clusters

# Perform postfix clustering if possible
if actual_postfix_n_clusters > 0:
    # Generate embeddings for unique postfixes using OpenAI
    print(f"Generating embeddings for {len(unique_postfixes)} postfixes using OpenAI model: {embedding_model_name}...")
    try:
        response = client.embeddings.create(
            input=list(unique_postfixes), # Input should be a list of strings
            model=embedding_model_name
        )
        postfix_embeddings = np.array([embedding.embedding for embedding in response.data])
        print("Postfix embeddings generated.")

        # Perform clustering on postfix embeddings
        print(f"Performing Agglomerative Clustering into {actual_postfix_n_clusters} clusters...")
        try:
            clustering_post = AgglomerativeClustering(
                n_clusters=actual_postfix_n_clusters,
                metric='cosine',
                linkage='average'
            )
            postfix_cluster_labels = clustering_post.fit_predict(postfix_embeddings)
            print(f"Postfix clustering complete. Found {len(np.unique(postfix_cluster_labels))} clusters.")

            # Create a mapping from original postfix to cluster label
            postfix_cluster_map = dict(zip(unique_postfixes, postfix_cluster_labels))

            # Map the cluster labels back to the original DataFrame
            df['PostfixCluster'] = df['FilePostfix'].map(postfix_cluster_map)

            # Get unique cluster labels for plotting
            unique_postfix_clusters = sorted(df['PostfixCluster'].unique())

            # Optional: Print postfixes per cluster for inspection
            print("\nPostfixes per cluster:")
            for cluster_id in unique_postfix_clusters:
                postfixes_in_cluster = [post for post, label in postfix_cluster_map.items() if label == cluster_id]
                print(f"Postfix Cluster {cluster_id}: {', '.join(postfixes_in_cluster)}")
            print("-" * 20)

        except Exception as e:
            print(f"Error during postfix clustering: {e}")
            print("Skipping postfix clustering and using original postfixes.")
            df['PostfixCluster'] = df['FilePostfix']
            unique_postfix_clusters = sorted(df['PostfixCluster'].unique()) # Use original postfixes
            postfix_cluster_map = {post: post for post in unique_postfix_clusters} # Map to self

    except Exception as e: # Catch exception from embedding generation
        print(f"Error during postfix embedding generation: {e}")
        print("Skipping postfix clustering and using original postfixes.")
        df['PostfixCluster'] = df['FilePostfix']
        unique_postfix_clusters = sorted(df['PostfixCluster'].unique()) # Use original postfixes
        postfix_cluster_map = {post: post for post in unique_postfix_clusters} # Map to self

else:
    # Case where actual_postfix_n_clusters is 0
    print("Skipping postfix clustering due to insufficient unique postfixes.")
    df['PostfixCluster'] = df['FilePostfix'] # Use original postfixes
    unique_postfix_clusters = sorted(df['PostfixCluster'].unique()) # Use original postfixes
    postfix_cluster_map = {post: post for post in unique_postfix_clusters} # Map to self


# Convert to DataFrame and count frequencies of unique triplets (Agent, Objective Cluster, Postfix Cluster)
# Now grouping by the new 'ObjectiveCluster' and 'PostfixCluster' columns
triplet_counts = df.groupby(['Agent', 'ObjectiveCluster', 'PostfixCluster']).size().reset_index(name='Frequency')

print(f"Found {len(triplet_counts)} unique Agent-ObjectiveCluster-PostfixCluster triplets.")

# --- Plotting ---

# Set font sizes for NeurIPS suitability
plt.style.use('seaborn-v0_8-colorblind') # A clean and professional style

plt.rcParams.update({'font.size': 10}) # Adjust base font size
plt.rcParams.update({'axes.labelsize': 12})
plt.rcParams.update({'xtick.labelsize': 9})
plt.rcParams.update({'ytick.labelsize': 9})
plt.rcParams.update({'legend.fontsize': 10})
plt.rcParams.update({'figure.titlesize': 14})
plt.rcParams.update({'font.family': 'sans-serif'}) # Use a common sans-serif font
plt.rcParams.update({'font.sans-serif': ['DejaVu Sans', 'Arial']}) # Specify preferred sans-serif fonts

# Get unique categories for axes and colors
# Y-axis: Security Objective Clusters
# Use unique_objective_clusters from the clustering step (or original if clustering failed)
# The labels will be the cluster IDs (integers) or original objectives (strings)
# Sorting ensures consistent order on the axis
unique_objective_clusters_sorted = sorted(unique_objective_clusters)

# X-axis: File Postfix Clusters
# Use unique_postfix_clusters from the clustering step (or original if clustering failed)
# The labels will be the cluster IDs (integers) or original postfixes (strings)
# Sorting ensures consistent order on the axis
unique_postfix_clusters_sorted = sorted(unique_postfix_clusters)

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


# Determine bubble size scaling
min_freq = triplet_counts['Frequency'].min()
max_freq = triplet_counts['Frequency'].max()

min_bubble_size = 50
scale_factor = 500

freq_range = max_freq - min_freq
if freq_range == 0:
    triplet_counts['BubbleSize'] = min_bubble_size
else:
    triplet_counts['BubbleSize'] = triplet_counts['Frequency'].apply(
        lambda freq: min_bubble_size + (freq - min_freq) * (scale_factor - min_bubble_size) / freq_range
    )

# Create the plot
# Adjust figure width based on number of postfix clusters, height based on objective clusters
fig_width = max(8, len(unique_postfix_clusters_sorted) * 1.0)
fig_height = max(6, len(unique_objective_clusters_sorted) * 0.8)
fig, ax = plt.subplots(figsize=(fig_width, fig_height))

# We need to map the numerical/string cluster labels to numerical positions for the scatter plot
objective_cluster_to_pos = {cluster: i for i, cluster in enumerate(unique_objective_clusters_sorted)} # Use sorted cluster labels
postfix_cluster_to_pos = {cluster: i for i, cluster in enumerate(unique_postfix_clusters_sorted)} # Use sorted cluster labels

# Use the mapped positions for plotting
triplet_counts['ObjectiveClusterPos'] = triplet_counts['ObjectiveCluster'].map(objective_cluster_to_pos)
triplet_counts['PostfixClusterPos'] = triplet_counts['PostfixCluster'].map(postfix_cluster_to_pos)

# Add some jitter to the positions
jitter_strength = 0.2
triplet_counts['PostfixClusterPos_jittered'] = triplet_counts['PostfixClusterPos'] + np.random.uniform(-jitter_strength, jitter_strength, size=len(triplet_counts))
triplet_counts['ObjectiveClusterPos_jittered'] = triplet_counts['ObjectiveClusterPos'] + np.random.uniform(-jitter_strength, jitter_strength, size=len(triplet_counts))


scatter = ax.scatter(
    x=triplet_counts['PostfixClusterPos_jittered'], # X-axis is Postfix Cluster Position
    y=triplet_counts['ObjectiveClusterPos_jittered'],       # Y-axis is Objective Cluster Position
    s=triplet_counts['BubbleSize'],
    c=triplet_counts['Agent'].map(agent_color_map),
    alpha=0.7,
    edgecolors='w',
    linewidths=0.5
)

# Set axis ticks and labels using the unique categories/clusters
# X-axis: Postfix Clusters
ax.set_xticks(range(len(unique_postfix_clusters_sorted)))
ax.set_xticklabels(unique_postfix_clusters_sorted, rotation=45, ha='right') # Use sorted cluster labels
# Y-axis: Security Objective Clusters
ax.set_yticks(range(len(unique_objective_clusters_sorted)))
ax.set_yticklabels(unique_objective_clusters_sorted) # Use sorted cluster labels

# Set axis limits to center the ticks
ax.set_xlim(-0.5, len(unique_postfix_clusters_sorted) - 0.5)
ax.set_ylim(-0.5, len(unique_objective_clusters_sorted) - 0.5)


# Add labels and title
ax.set_xlabel("File Postfix Cluster") # Updated label
ax.set_ylabel("Security Objective Cluster") # Updated label
ax.set_title("Agent, Objective Cluster, and File Postfix Cluster Relationships by Frequency") # Updated title

# Add grid lines aligned with ticks
ax.grid(True, linestyle='--', alpha=0.6, which='both')

# Create a legend for agents (colors)
legend_elements = [plt.Line2D([0], [0], marker='o', color='w', label=agent,
                             markerfacecolor=agent_color_map[agent], markersize=10)
                  for agent in unique_agents]

ax.legend(handles=legend_elements, title="Agent", loc='upper left', bbox_to_anchor=(1.05, 1), borderaxespad=0.)

# Add a separate legend for bubble size (frequency)
freq_legend_values = sorted(list(triplet_counts['Frequency'].quantile([0.25, 0.5, 0.75])))
if min_freq not in freq_legend_values: freq_legend_values.insert(0, min_freq)
if max_freq not in freq_legend_values and max_freq > freq_legend_values[-1]: freq_legend_values.append(max_freq)

size_legend_values = []
for freq in freq_legend_values:
    if freq_range == 0:
        size_legend_values.append(min_bubble_size)
    else:
        size_legend_values.append(min_bubble_size + (freq - min_freq) * (scale_factor - min_bubble_size) / freq_range)

size_legend_elements = [plt.Line2D([0], [0], marker='o', color='w', label=f'{int(freq)}',
                                 markerfacecolor='gray', markersize=size/10)
                       for freq, size in zip(freq_legend_values, size_legend_values)]

size_legend = ax.legend(handles=size_legend_elements, title="Frequency", loc='upper left', bbox_to_anchor=(1.05, 0.6), borderaxespad=0.)
ax.add_artist(size_legend)

# Adjust layout
plt.tight_layout(rect=[0, 0, 0.8, 1])

# Save the plot
output_filename = "agent_objective_cluster_postfix_cluster_bubble_grid.pdf" # New filename
plt.savefig(output_filename, format='pdf', bbox_inches='tight')

print(f"Plot saved as {output_filename}")

# Show the plot (optional)
# plt.show()
