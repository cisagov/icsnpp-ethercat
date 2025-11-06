# @TEST-EXEC: zeek -C -r ${TRACES}/ethercat_example.pcap %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service < conn.log > conn.tmp && mv conn.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ecat_aoe_info.log
# @TEST-EXEC: btest-diff ecat_coe_info.log
# @TEST-EXEC: btest-diff ecat_dev_info.log
# @TEST-EXEC: btest-diff ecat_log_address.log
# @TEST-EXEC: btest-diff ecat_registers.log
#
# @TEST-DOC: Test ECAT analyzer with small trace.

@load icsnpp/ethercat
