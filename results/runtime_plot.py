import re
from datetime import datetime
import matplotlib.pyplot as plt
import pandas as pd

log_data = """
[2025-05-06 15:03:53] Starting analysis for IP=adc_ctrl | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 15:12:43] Finished analysis for IP=adc_ctrl
[2025-05-06 15:12:43] Starting analysis for IP=aes | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 15:31:01] Finished analysis for IP=aes
[2025-05-06 15:31:01] Starting analysis for IP=csrng | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 15:51:25] Finished analysis for IP=csrng
[2025-05-06 15:51:25] Starting analysis for IP=ent_src | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 16:14:29] Finished analysis for IP=ent_src
[2025-05-06 16:14:29] Starting analysis for IP=hmac | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 16:22:48] Finished analysis for IP=hmac
[2025-05-06 16:22:48] Starting analysis for IP=keymgr | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 16:41:52] Finished analysis for IP=keymgr
[2025-05-06 16:41:52] Starting analysis for IP=kmac | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 16:58:32] Finished analysis for IP=kmac
[2025-05-06 16:58:32] Starting analysis for IP=lc_ctrl | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 17:07:24] Finished analysis for IP=lc_ctrl
[2025-05-06 17:07:24] Starting analysis for IP=otbn | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 17:14:30] Finished analysis for IP=otbn
[2025-05-06 17:14:30] Starting analysis for IP=otp_ctrl | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 17:28:12] Finished analysis for IP=otp_ctrl
[2025-05-06 17:28:12] Starting analysis for IP=prim | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 17:33:51] Finished analysis for IP=prim
[2025-05-06 17:33:51] Starting analysis for IP=tlul | agent=agentic | model=sonnet | temperature=0.2
[2025-05-06 17:41:21] Finished analysis for IP=tlul
"""

def parse_log_and_plot(log_content):
    """
    Parses log data, calculates runtimes, and generates a plot.

    Args:
        log_content (str): A string containing the log data.
    """
    # Regex to capture timestamp, action (Starting/Finished), and IP
    log_pattern = re.compile(r"\[(.*?)\] (Starting|Finished) analysis for IP=(\w+)")

    parsed_data = {}

    for line in log_content.strip().split('\n'):
        match = log_pattern.match(line)
        if match:
            timestamp_str, action, ip_name = match.groups()
            # Assuming the year is consistent and recent, like the current year or specified in log.
            # For this specific log, the year 2025 is used.
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            if ip_name not in parsed_data:
                parsed_data[ip_name] = {}

            if action == "Starting":
                parsed_data[ip_name]['start_time'] = timestamp
            elif action == "Finished":
                parsed_data[ip_name]['end_time'] = timestamp

    runtimes = {}
    for ip, times in parsed_data.items():
        if 'start_time' in times and 'end_time' in times:
            runtime_seconds = (times['end_time'] - times['start_time']).total_seconds()
            runtimes[ip] = runtime_seconds / 60  # Runtime in minutes
        else:
            print(f"Warning: Missing start or end time for IP={ip}")


    if not runtimes:
        print("No valid runtime data could be extracted. Plot will not be generated.")
        return

    # Create a DataFrame for easier plotting and sorting
    df_runtimes = pd.DataFrame(list(runtimes.items()), columns=['IP', 'Runtime (minutes)'])
    df_runtimes = df_runtimes.sort_values(by='IP', ascending=True)

    # --- Plotting ---
    # For a NeurIPS paper, clarity, and professionalism are key.
    # A horizontal bar chart can be very effective if IP names are long or numerous.
    # For this number of IPs, a vertical bar chart is also fine.
    # We will use a style often seen in academic papers.

    plt.style.use('seaborn-v0_8-colorblind') # A clean and professional style

    fig, ax = plt.subplots(figsize=(10, 2.2)) # Good figure size for readability

    # Create the bar plot
    bars = ax.bar(df_runtimes['IP'], df_runtimes['Runtime (minutes)'], color='steelblue', edgecolor='black')

    # Adding labels and formatting
    ax.set_ylabel('Runtime (minutes)', fontsize=14, labelpad=10)
    ax.set_xlabel('IP Block', fontsize=14, labelpad=10) # Changed from 'IP' to 'IP Block' for clarity

    # Improve tick label readability
    plt.xticks( fontsize=12)
    plt.yticks(fontsize=12)

    # Add a light grid for the y-axis for easier value reading
    ax.yaxis.grid(True, linestyle='--', which='major', color='grey', alpha=.25)
    ax.set_axisbelow(True) # Ensure grid is behind bars

    # Remove plot title as requested by the user
    # ax.set_title('Analysis Runtime per IP Block', fontsize=16, pad=20)

    # Remove top and right spines for a cleaner look (common in some academic styles)
    #ax.spines['top'].set_visible(False)
    #ax.spines['right'].set_visible(False)

    # Adjust layout to prevent labels from overlapping
    plt.tight_layout()
    fig.subplots_adjust(left=0, right=1, top=0.9, bottom=0.1)

    # Save the plot in PDF format (vector graphics are good for papers)
    pdf_filename = "neurips_runtime_plot.pdf"
    plt.savefig(pdf_filename, format="pdf", bbox_inches="tight")
    print(f"\nPlot saved to {pdf_filename}")

    # --- Output Runtimes ---
    print("\nCalculated Runtimes (in minutes):")
    # Print sorted runtimes
    for index, row in df_runtimes.iterrows():
        print(f"{row['IP']}: {row['Runtime (minutes)']:.2f} minutes")

    # Save runtimes to a text file
    txt_filename = "runtimes_summary.txt"
    with open(txt_filename, "w") as f:
        f.write("Calculated Runtimes (in minutes):\n")
        f.write("----------------------------------\n")
        for index, row in df_runtimes.iterrows():
            f.write(f"{row['IP']}: {row['Runtime (minutes)']:.2f} minutes\n")
    print(f"Runtimes also saved to {txt_filename}")

if __name__ == '__main__':
    # Call the main function with the log data
    parse_log_and_plot(log_data)