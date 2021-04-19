## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
module PacketAnalyzer::ECAT;

export{

    #############################################################
    #########            Ethercat commands              #########
    #############################################################
    const Ecat_Cmd = {
        [0x00] = "NOP",
        [0x01] = "Auto Increment Physical Read",
        [0x02] = "Auto Increment Physical Write",
        [0x03] = "Auto Increment Physical ReadWrite",
        [0x04] = "Configured Addr Physical Read",
        [0x05] = "Configured Addr Physical Write",
        [0x06] = "Configured Addr Physical ReadWrite",
        [0x07] = "Broadcast Read",
        [0x08] = "Broadcast Write",
        [0x09] = "Broadcast ReadWrite",
        [0x0A] = "Logical Read",
        [0x0B] = "Logical Write",
        [0x0C] = "Logical ReadWrite",
        [0x0D] = "Auto Increment Physical Read Mult Write",
        [0x0E] = "Configured Addr Physical Read Mult Write",


    } &default = function(n: count): string {return fmt("Unknown CMD Cmd-0x%02x", n); };

    #############################################################
    #########              AoE commands                 #########
    #############################################################
    const Ecat_AoE_Cmd = {
        [0x0000] = "NOP",
        [0x0001] = "ADS Read Device Info",
        [0x0002] = "ADS Read",
        [0x0003] = "ADS Write",
        [0x0004] = "ADS Read State",
        [0x0005] = "ADS Write Control",
        [0x0006] = "ADS Add Device Notification",
        [0x0007] = "ADS Delete Device Notification",
        [0x0008] = "ADS Device Notification",
        [0x0009] = "ADS Read Write",


    } &default = function(n: count): string {return fmt("Unknown CMD Cmd-0x%02x", n); };

    ############################################################################
    ######### Ecat_Registers:                                          #########
    ######### Description: Register address for reading and writing    #########
    ############################################################################
    const Ecat_Registers = {
        [0x0000] = "Type",
        [0x0001] = "Revision",
        [0x0002] = "Build", 
        [0x0004] = "FMMUSPT", 
        [0x0005] = "SyncManagers", 
        [0x0006] = "RAMSize", 
        [0x0007] = "PortDescriptor",
        [0x0008] = "ESC_Features", 
        [0x0010] = "CSAddr", 
        [0x0012] = "CSAlias", 
        [0x0020] = "Reg_Write_En", 
        [0x0021] = "Reg_Write_Prot", 
        [0x0030] = "ESC_Write_En", 
        [0x0031] = "ESC_Write_Prot", 
        [0x0040] = "ESC_Rst_Ecat",
        [0x0041] = "ESC_Rst_Pdi", 
        [0x0100] = "ESC_DL_Ctl", 
        [0x0108] = "Phy_RD_WR_Offs", 
        [0x0110] = "ESC_DL_Stat", 
        [0x0120] = "AL_Ctl", 
        [0x0130] = "AL_Stat", 
        [0x0134] = "AL_Stat_Code", 
        [0x0138] = "RUN_Led_Ovrd", 
        [0x0139] = "ERR_Led_Ovrd", 
        [0x0140] = "PDI_Ctl", 
        [0x0141] = "ESC_Conf", 
        [0x014E] = "PDI_Info", 
        [0x0150] = "PDI_Conf",
        [0x0152] = "PDI_Onchip_Conf",
        [0x0151] = "Sync_Latc_Pdi",
        [0x0200] = "ECAT_Ev_Msk",
        [0x0204] = "PDI AL Event Mask",
        [0x0210] = "ECAT Event Request",
        [0x0220] = "AL Event Request",
        [0x0300] = "RX_Err_Cnt",
        [0x0308] = "Fwd_Rx_Err_Cnt",
        [0x030C] = "ECAT_Proc_Err_Cnt",
        [0x030D] = "PDI_Err_Cnt",
        [0x030E] = "PDI_Err_Code",
        [0x0310] = "LLC",
        [0x0400] = "WTD_Div",
        [0x0410] = "WTD_Time_PDI",
        [0x0420] = "WTD_Time_Proc_Data",
        [0x0440] = "WTD_Stat_Proc_Data",
        [0x0442] = "WTD_Cnt_Proc_Data",
        [0x0443] = "WTD_Cnt_PDI",
        [0x0500] = "SII_EEPROM_Intr",
        [0x0510] = "MII_Mang_Intr",
        [0x0600] = "FMMU",
        [0x0800] = "SyncManager",
        [0x0900] = "Dist_Clk",
        [0x0E00] = "ESC_Specf-Reg ",
        [0x0F00] = "Dig_IO_Data",
        [0x0F10] = "GP_Out_Data",
        [0x0F18] = "GP_In",
        [0x0F80] = "USR_Ram",
        [0x1000] = "PDI_Dig_IO_Data",
        [0x1004] = "PD_Ram",
    }&default = function(n: count): string {return fmt("Unknown Register Reg-0x%02x", n); };

}
