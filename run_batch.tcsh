#!/bin/tcsh

# List of IPs to analyze
set ip_list = (aes hmac uart spi_device spi_host i2c keymgr rom_ctrl adc_ctrl csrng otbn otp_ctrl lc_ctrl prim pwrmgr sysrst_ctrl all)

# Ensure log directory exists
mkdir -p logs


# Log file for tracking overall run progress
set run_log = "run.log"
touch $run_log

foreach ip ($ip_list)
    set start_ts = `date "+%Y-%m-%d %H:%M:%S"`
    echo "[$start_ts] Starting analysis for $ip" >> $run_log

    # Redirect both stdout and stderr to the same file using >&
    python security_agents.py --ip $ip >& logs/${ip}.log

    set end_ts = `date "+%Y-%m-%d %H:%M:%S"`
    echo "[$end_ts] Finished analysis for $ip" >> $run_log
end