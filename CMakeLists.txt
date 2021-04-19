cmake_minimum_required(VERSION 3.0)

project(Plugin)

include(ZeekPlugin)

zeek_plugin_begin(ICSNPP ETHERCAT)
    zeek_plugin_cc(src/ECAT.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()