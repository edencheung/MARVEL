set sh_continue_on_error true
set enable_lint true

[LINT_TAGS]

analyze -format sverilog -vcs { -f [FILELIST]}
elaborate [TOP_MODULE]

check_lint

report_lint -verbose -file [RESULT_FILE] 