// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
// ECAT_ENUMS.h
//
// Ethercat Enums - Defines constants for Ethercat devices
//
// Author:  Devin Vollmer
// Contact: devin.vollmer@inl.gov

#pragma once
// -----------------------------------Ethercat Mailbox-----------------------------------------
// Description: Ethercat mailbox types
// --------------------------------------------------------------------------------------------
enum {
    ecat_mbx_none   = 0x00,
    ecat_mbx_aoe    = 0x01, // ADS over Ethernet
    ecat_mbx_eoe    = 0x02, // Ethernet over EtherCAT 
    ecat_mbx_coe    = 0x03, // CANopen over EtherCAT 
    ecat_mbx_foe    = 0x04, // File-Access over EtherCAT 
    ecat_mbx_soe    = 0x05, // Servo-Profile over EtherCAT 
    ecat_mbx_voe    = 0x0F  // Vendor specific 
};


// ---------------------------------Ethercat datagram Type-------------------------------------
// Description: Function type of ethercat datagram
// --------------------------------------------------------------------------------------------
enum {
    ecat_datagram_none = 0x00, //Dummy.
    ecat_datagram_aprd = 0x01, //Auto Increment Physical Read.
    ecat_datagram_apwr = 0x02, //Auto Increment Physical Write.
    ecat_datagram_aprw = 0x03, //Auto Increment Physical ReadWrite.
    ecat_datagram_fprd = 0x04, //Configured Address Physical Read.
    ecat_datagram_fpwr = 0x05, //Configured Address Physical Write.
    ecat_datagram_fprw = 0x06, //Configured Address Physical ReadWrite.
    ecat_datagram_brd  = 0x07, //Broadcast Read.
    ecat_datagram_bwr  = 0x08, //Broadcast Write.
    ecat_datagram_brw  = 0x09, //Broadcast ReadWrite.
    ecat_datagram_lrd  = 0x0A, //Logical Read.
    ecat_datagram_lwr  = 0x0B, //Logical Write.
    ecat_datagram_lrw  = 0x0C, //Logical ReadWrite.
    ecat_datagram_armw = 0x0D, //Auto Increment Physical Read Multiple
                               //Write. 
    ecat_datagram_frmw = 0x0E, //Configured Address Physical Read Multiple
                               //Write.
};

// -----------------------------------Ethercat Register----------------------------------------
// Description: Register address for reading and writing 
// --------------------------------------------------------------------------------------------
enum {
    dev_type                    = 0x0000,
    revision                    = 0x0001,
    build                       = 0x0002, // Build Rev, two byte register length
    fmmuspt                     = 0x0004, // FMMUs supported
    sync_managers               = 0x0005, // SyncManagers supported 
    ram_size                    = 0x0006, // Size of physical ram 
    port_descriptor             = 0x0007,
    esc_features                = 0x0008, //ESC Features supported 2 byte register length
    cs_addr                     = 0x0010, // Configured Station Address 2 byte register value
    cs_alias                    = 0x0012, // Configured Station Alias 2 byte register value
    reg_write_en                = 0x0020, // Register Write Enable
    reg_write_prot              = 0x0021, // Register Write Protection
    esc_write_en                = 0x0030, // ESC Write Enable 
    esc_write_prot              = 0x0031, // ESC Write Protection
    esc_rst_ecat                = 0x0040, // ESC Reset ECAT 
    esc_rst_pdi                 = 0x0041, // ESC Reset PDI
    esc_dl_ctl                  = 0x0100, // 4 bytes ESC DL Control
    phy_rd_wr_offs              = 0x0108, // 2 bytes Physical Read/Write Offset 
    esc_dl_stat                 = 0x0110, // 2bytes ESC DL Status
    al_ctrl                     = 0x0120, // 2bytes AL Control
    al_stat                     = 0x0130, // 2bytes AL Status
    al_stat_code                = 0x0134, // 2bytes AL Status Code
    run_led_ovrd                = 0x0138, // RUN LED Override
    err_led_ovrd                = 0x0139, // ERR LED Override
    pdi_ctrl                    = 0x0140, // PDI Control
    esc_conf                    = 0x0141, // ESC Configuration 
    pdi_info                    = 0x014E, // 2bytes PDI Information
    pdi_conf                    = 0x0150, // 4 bytes PDI Configuration
    pdi_onchip_conf             = 0x0152, // 2 byte PDI On-chip bus extended configuration
    sync_latc_pdi               = 0x0151, // Bit [1:0] Sync/Latch[1:0] PDI Configuration
    ecat_ev_msk                 = 0x0200, // 2 byte ECAT Event Mask
    pdi_al_ev_msk               = 0x0204, // 4 byte PDI AL Event Mask
    ecat_ev_req                 = 0x0210, // 2 byte ECAT Event Request
    al_ev_req                   = 0x0220, // 4 byte AL Event Request
    rx_err_cnt                  = 0x0300, // 8 byte RX Error Counter 
    fwd_rx_err_cnt              = 0x0308, // 4 byte Forwarded RX Error Counter 
    ecat_proc_err_cnt           = 0x030C, // ECAT Processing Unit Error Counter 
    pdi_err_cnt                 = 0x030D, // PDI Error Counter 
    pdi_err_code                = 0x030E, // PDI Error Code 
    llc                         = 0x0310, // 4 byte Lost Link Counter 
    wtd_div                     = 0x0400, // 2 byte Watchdog Divider 
    wtd_time_pdi                = 0x0410, // 2 byte Watchdog Time PDI 
    wtd_time_proc_data          = 0x0420, // 2 byte Watchdog Time Process Data 
    wtd_stat_proc_data          = 0x0440, // 2 byte Watchdog Status Process Data 
    wtd_cnt_proc_data           = 0x0442, // Watchdog Counter Process Data 
    wtd_cnt_pdi                 = 0x0443, // Watchdog Counter PDI 
    sii_eeprom_intr             = 0x0500, // 16 byte SII EEPROM Interface 
    mii_mang_intr               = 0x0510, // 6 byte MII Management Interface 
    fmmu                        = 0x0600, // 0xff bytes FMMU 
    sync_manager                = 0x0800, // 0x7f bytes SyncManager 
    dist_clk                    = 0x0900, // 0xff bytes Distributed Clocks 
    esc_specf_reg               = 0x0E00, // 0xff ESC specific registers 
    dig_io_data                 = 0x0F00, // 4 byte Digital I/O Output Data 
    gp_out_data                 = 0x0F10, // 8 byte General Purpose Outputs 
    gp_in                       = 0x0F18, // 8 byte rGeneral Purpose Inputs 
    usr_ram                     = 0x0F80, // 80 bytes User RAM 
    pd_ram                      = 0x1000, // 4 byte PDI Digital I/O Input Data 

};






































