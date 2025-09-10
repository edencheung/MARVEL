#!/bin/bash

# List of IPs to analyze
ip_list=(aes hmac adc_ctrl) # uart spi_device spi_host i2c keymgr rom_ctrl adc_ctrl csrng otbn otp_ctrl lc_ctrl prim pwrmgr sysrst_ctrl all
model_list=(openai)
temperature_list=(0.1 0.2 0.3)

# Ensure log directory exists
mkdir -p logs

# Log file for tracking overall run progress
run_log="run.log"
touch "$run_log"

for ip in "${ip_list[@]}"; do
  for model in "${model_list[@]}"; do
    for temperature in "${temperature_list[@]}"; do

      timestamp=$(date "+%Y-%m-%d %H:%M:%S")
      echo "[$timestamp] Starting analysis for IP=$ip | agent=agentic | model=$model | temperature=$temperature" >> "$run_log"

      # Run your script (uncomment when ready)
      python security_agents.py --agent agentic --model "$model" --temp "$temperature" --ip "$ip" &> "logs/${ip}_${model}_${temperature}.log"

      timestamp=$(date "+%Y-%m-%d %H:%M:%S")
      echo "[$timestamp] Finished analysis for IP=$ip" >> "$run_log"

    done
  done
done
