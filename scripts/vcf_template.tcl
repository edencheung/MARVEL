set_fml_appmode FPV

set design [TOP_MODULE]
read_file -top $design -format sverilog -sva -vcs {-f [FILELIST]}

create_clock [CLK] -period 100
create_reset [RST] -sense [RST_ACTIVE]

sim_run -stable
sim_save_reset

check_fv -block

report_fv -verbose > [RESULT_FILE]