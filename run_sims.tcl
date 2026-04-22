# run_sims.tcl
set log_dir "./results/simulation"
file mkdir $log_dir

# Suppress the filemgmt warnings that flood the console
set_msg_config -id {filemgmt 56-199} -suppress

# Close any simulation that might have been left open from a previous crash/abort
catch {close_sim}

set testbenches {
    tb_aes_subbytes
    tb_aes_shiftrows
    tb_aes_mixcolumns
    tb_aes_addroundkey
    tb_aes_key_expansion
    tb_aes_core
    tb_hamming_weight
    tb_uart_tx
    tb_uart_rx
    tb_control_fsm
    tb_aes_subbytes_masked
    tb_aes_mixcolumns_masked
    tb_mask_refresh
    tb_aes_core_masked
    tb_ring_oscillator_trng
    tb_trng_validator
    tb_timing_randomizer
    tb_aes_core_hardened
    tb_aes_hardened
}

set passed 0
set failed 0
set summary {}

foreach tb $testbenches {
    puts ""
    puts "============================================"
    puts "Running: $tb"
    puts "============================================"

    set_property top $tb [get_filesets sim_1]
    set_property top_lib xil_defaultlib [get_filesets sim_1]

    # Launch simulation — most testbenches finish here due to $finish
    launch_simulation

    # Only run more if simulation did not already finish
    # Use catch so a "simulation already finished" error doesn't abort the script
    # Run for a bounded time rather than "run all" which can hang forever
    # 10ms sim time covers all testbenches including UART ones
    catch {run 10ms}

    # Wait briefly for log flush
    after 300

    # Copy the xsim log
    set proj_dir  [get_property DIRECTORY [current_project]]
    set proj_name [get_property NAME      [current_project]]
    set xsim_log  "$proj_dir/${proj_name}.sim/sim_1/behav/xsim/simulate.log"
    set out_file  "$log_dir/${tb}.log"

    if {[file exists $xsim_log]} {
        file copy -force $xsim_log $out_file

        set fh      [open $xsim_log r]
        set content [read $fh]
        close $fh

        if {[string match "*ALL TESTS PASSED*" $content]} {
            puts "  Result: PASS"
            incr passed
            lappend summary "PASS  $tb"
        } elseif {[string match "*FAIL*" $content]} {
            puts "  Result: FAIL"
            incr failed
            lappend summary "FAIL  $tb"
        } else {
            puts "  Result: UNKNOWN (check log)"
            lappend summary "????  $tb"
        }
    } else {
        puts "  WARNING: log not found at $xsim_log"
        lappend summary "????  $tb (no log)"
    }

    close_sim
}

# Write summary file
set summary_file "$log_dir/SUMMARY.txt"
set fh [open $summary_file w]
puts $fh "AEGIS Simulation Summary"
puts $fh "========================"
puts $fh ""
foreach line $summary {
    puts $fh $line
}
puts $fh ""
puts $fh "Total: $passed passed, $failed failed"
close $fh

puts ""
puts "============================================"
puts "  SIMULATION SUMMARY"
puts "============================================"
foreach line $summary {
    puts "  $line"
}
puts ""
puts "  Total: $passed passed, $failed failed"
puts "  Saved to: $log_dir/SUMMARY.txt"
puts "============================================"