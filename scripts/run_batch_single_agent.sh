#!/bin/bash


# Ensure log directory exists
mkdir -p logs
run_log="run_single_agents.log"
touch "$run_log"

run_analysis() {
    local ip="$1"
    local agent="$2"
    local model="$3"
    local file="$4"
    local top_module="$5"
    local security_objective="$6"
    local bug_ex="$7"

    local log_file="$run_log"

    local start_ts
    start_ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$start_ts] Starting analysis for IP=$ip | agent=$agent | model=$model | file=$file | top module=$top_module" >> "$log_file"
    
    source /home/eden/Desktop/Code/HACK@CHES/MARVEL/venv/bin/activate

    python3 src/main.py \
        --ip "$ip" \
        --agent "$agent" \
        --model "$model" \
        --design_file "$file" \
        --top_module "$top_module" \
        --security_objective "$security_objective" \
        --bug_ex "$bug_ex" \
        &> "logs/${ip}_${agent}_${model}_${top_module}.log"

    local end_ts
    end_ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$end_ts] Finished analysis for $ip" >> "$log_file"
}

# Verilator runs -> only require IP
# run_analysis "aes" "verilator" "openai" "" "" "" ""
# run_analysis "hmac" "verilator" "openai" "" "" "" ""
# run_analysis "adc_ctrl" "verilator" "openai" "" "" "" ""
# run_analysis "csrng" "verilator" "openai" "" "" "" ""
# run_analysis "keymgr" "verilator" "openai" "" "" "" ""
# run_analysis "lc_ctrl" "verilator" "openai" "" "" "" ""
# run_analysis "otbn" "verilator" "openai" "" "" "" ""
# run_analysis "prim" "verilator" "openai" "" "" "" ""
# run_analysis "otp_ctrl" "verilator" "openai" "" "" "" ""
# run_analysis "spi_tmp" "verilator" "openai" "" "" "" ""

# assertion runs -> require IP, top module and file
# run_analysis "aes" "assertion" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/aes/rtl/aes_core.sv" "aes_core" "data wiping/clearing" ""
# run_analysis "aes" "assertion" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/aes/rtl/aes_cipher_core.sv" "aes_cipher_core" "data wiping/clearing" ""
# run_analysis "aes" "assertion" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/aes/rtl/aes_reg_top.sv" "aes_reg_top" "data leaks" ""

# run_analysis "hmac" "assertion" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/hmac/rtl/hmac_reg_top.sv" "hmac_reg_top" "data leaks" ""
# run_analysis "csrng" "assertion" "openai" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/csrng/rtl/csrng_reg_top.sv" "csrng_reg_top" "data leaks" ""

# # Linter runs -> require IP, top module and file
# run_analysis "hmac" "linter" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/hmac/rtl/hmac_reg_top.sv" "hmac_reg_top" "FSM" ""
# run_analysis "csrng" "linter" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/csrng/rtl/csrng_reg_top.sv" "csrng_reg_top" "FSM" ""
# run_analysis "adc_ctrl" "linter" "openai" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/adc_ctrl/rtl/adc_ctrl_fsm.sv" "adc_ctrl_fsm" "FSM" ""

# # CWE
# run_analysis "otbn" "cwe" "sonnet" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/otbn/rtl/otbn_controller.sv" "otbn_controller" "data wiping/clearing" ""

# # Similar bug
# run_analysis "aes" "similar_bug" "sonnet" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/otbn/rtl/otbn_controller.sv" "" "" "assign test_fail_hi_pulse_o = 1'b0; assign test_fail_lo_pulse_o = 1'b0;"
# run_analysis "aes" "similar_bug" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/aes/rtl/aes_reg_top.sv" "aes_reg_top" "" "reg_rdata_next[31:0] = reg2hw.key[0].q;"
# run_analysis "hmac" "similar_bug" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/aes/rtl/hmac.sv" "hmac" "" "DIP_CLEAR:   data_in_prev_d = data_in;"
# run_analysis "hmac" "similar_bug" "deepseek" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/hmac/rtl/hmac_reg_top.sv" "hmac_reg_top" "" "reg_rdata_next = reg2hw.key_share0[0].q;"

# anomaly
run_analysis "hmac" "anomaly" "openai" "/home/eden/Desktop/Code/HACK@CHES/hackdate/hw/ip/hmac/rtl/hmac_reg_top.sv" "hmac_reg_top" "data wiping/clearing" ""
