## Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved."
## main.zeek
##
## Packet Analyzer Ethercat Analyzer - Contains the base script-layer 
##                                     functionality for processing events 
##                                     emitted from the analyzer.
##
## Author:   Devin Vollmer
## Contact:  devin.vollmer@inl.gov

module PacketAnalyzer::ECAT;

export {
    redef enum Log::ID += { LOG_ECAT_REGISTERS, LOG_ECAT_ADDRESS, LOG_ECAT_DEV_INFO, LOG_ECAT_AOE_INFO, 
                            LOG_ECAT_COE_INFO, LOG_ECAT_FOE_INFO, LOG_ECAT_SOE_INFO, LOG_ECAT_ARP_INFO};

    ###############################################################################################
    #############################  ECAT_REGISTER -> ecat_registers.log  ############################
    ###############################################################################################
    type ECAT_REGISTER: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        srcmac 			: string 	&log;                   ## Source Mac Address
        dstmac 			: string 	&log;                   ## Destination Mac Address
        Command         : string    &log;                   ## Ethercat Command
        Slave_Addr      : string    &log;                   ## Ethercat Slave Address
        Register_Type   : string    &log;                   ## Register Information
       	Register_Addr   : string 	&log;                   ## Memory Address being accessed
        data 		    : string    &log;                   ## Data to be read or wrote to memory address
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_registers: event(rec: ECAT_REGISTER);
    global log_policy_ecat_registers: Log::PolicyHook;

    ###############################################################################################
    ############################  ECAT_LOG_ADDR -> ecat_log_address.log  ###########################
    ###############################################################################################
    type ECAT_LOG_ADDR: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        srcmac 			: string 	&log;                   ## Source Mac Address
        dstmac 			: string 	&log;                   ## Destination Mac Address
        Log_Addr     	: string 	&log;                   ## Address data is being accessed from  
        Length 			: count 	&log;                   ## Length of data
        Command 		: string 	&log;                   ## Ethercat Command
        data 		    : string    &log;                   ## Data read or write
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_addr: event(rec: ECAT_LOG_ADDR);
    global log_policy_ecat_addr: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_DEV_INFO -> ecat_dev_info.log   ############################
    ###############################################################################################
    type ECAT_DEV_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        slave_id        : string    &log;                   ## Ethercat Slave Address
        revision        : string    &log;                   ## Default Zeek connection info (IP addresses, ports)
        dev_type        : string    &log;                   ## Number of functions per message
        build           : string    &log;                   ## Build version
        fmmucnt         : string    &log;                   ## Fieldbus Memory Management Unit supported channel count 
        smcount         : string    &log;                   ## Sync Manager count
        ports           : string    &log;                   ## Port Descriptor
        dpram           : string    &log;                   ## Ram size
        features        : string    &log;                   ## Features supported
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_dev: event(rec: ECAT_DEV_INFO);
    global log_policy_ecat_dev: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_AOE_INFO -> ecat_aoe_info.log   ############################
    ###############################################################################################
    type ECAT_AOE_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        targetid        : string    &log;                   ## Target Network ID
        targetport      : string    &log;                   ## Target Port
        senderid        : string    &log;                   ## Sender Network ID
        senderport      : string    &log;                   ## Sender Port
        cmd             : string    &log;                   ## Command
        stateflags      : string    &log;                   ## State Flags
        data            : string    &log;                   ## Command Data
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_aoe: event(rec: ECAT_AOE_INFO);
    global log_policy_ecat_aoe: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_COE_INFO -> ecat_coe_info.log   ############################
    ###############################################################################################
    type ECAT_COE_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        number          : string    &log;                   ## Message number
        Type            : string    &log;                   ## Message Type
        req_resp        : string    &log;                   ## Request or Response type
        index           : string    &log;                   ## Index
        subindex        : string    &log;                   ## Sub Index
        dataoffset      : string    &log;                   ## Data Offset
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_coe: event(rec: ECAT_COE_INFO);
    global log_policy_ecat_coe: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_FOE_INFO -> ecat_foe_info.log   ############################
    ###############################################################################################
    type ECAT_FOE_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        opCode          : string    &log;                   ## Operation Code
        reserved        : string    &log;                   ## Reserved
        packet_num      : string    &log;                   ## Packet number
        error_code      : string    &log;                   ## Error Code
        filename        : string    &log;                   ## Filename
        data            : string    &log;                   ## Transferred Data
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_foe: event(rec: ECAT_FOE_INFO);
    global log_policy_ecat_foe: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_SOE_INFO -> ecat_soe_info.log   ############################
    ###############################################################################################
    type ECAT_SOE_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        opCode          : string    &log;                   ## Command sent for controller
        incomplete      : string    &log;                   ## Function check to determine if it has been processed
        error           : string    &log;                   ## Error message
        drive_num       : string    &log;                   ## Drive number for command
        element_flags   : string    &log;                   ## Element Flags
        index           : string    &log;                   ## Message Index
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_soe: event(rec: ECAT_SOE_INFO);
    global log_policy_ecat_soe: Log::PolicyHook;

    ###############################################################################################
    #############################  ECAT_ARP_INFO -> ecat_arp_info.log   ############################
    ###############################################################################################
    type ECAT_ARP_INFO: record {
        ts              : time      &log;                   ## Timestamp for when the event happened
        arp_type        : string    &log;                   ## Arp command
        mac_src         : string    &log;                   ## Source Mac address
        mac_dst         : string    &log;                   ## Destination Mac address
        SPA             : addr      &log;                   ## Sender protocol address
        SHA             : string    &log;                   ## Sender hardware address
        TPA             : addr      &log;                   ## Target protocol address
        THA             : string    &log;                   ## Target hardware address
        # ## TODO: Add other fields here that you'd like to log.
    };
    global log_ecat_arp: event(rec: ECAT_ARP_INFO);
    global log_policy_ecat_arp: Log::PolicyHook;
}


###################################################################################################
##########   Defines Ethercat logs, ecat_log_address, ecat_dev_info, ecat_aoe_info     ############
##########   ecat_dev_info, ecat_coe_info, ecat_foe_info, ecat_soe_info, ecat_arp_info ############
##########                                                                             ############
##########   Registers Ethercat Packet Analyzer, IP analyzer, and ARP analyzer         ############
###################################################################################################
event zeek_init() &priority=20 {

	Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_REGISTERS, [$columns=ECAT_REGISTER, $ev=log_ecat_registers, $path="ecat_registers", $policy=log_policy_ecat_registers]);
	Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_ADDRESS, [$columns=ECAT_LOG_ADDR, $ev=log_ecat_addr, $path="ecat_log_address", $policy=log_policy_ecat_addr]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_DEV_INFO, [$columns=ECAT_DEV_INFO, $ev=log_ecat_dev, $path="ecat_dev_info", $policy=log_policy_ecat_dev]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_AOE_INFO, [$columns=ECAT_AOE_INFO, $ev=log_ecat_aoe, $path="ecat_aoe_info", $policy=log_policy_ecat_aoe]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_COE_INFO, [$columns=ECAT_COE_INFO, $ev=log_ecat_coe, $path="ecat_coe_info", $policy=log_policy_ecat_coe]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_FOE_INFO, [$columns=ECAT_FOE_INFO, $ev=log_ecat_foe, $path="ecat_foe_info", $policy=log_policy_ecat_foe]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_SOE_INFO, [$columns=ECAT_SOE_INFO, $ev=log_ecat_soe, $path="ecat_soe_info", $policy=log_policy_ecat_soe]);
    Log::create_stream(PacketAnalyzer::ECAT::LOG_ECAT_ARP_INFO, [$columns=ECAT_ARP_INFO, $ev=log_ecat_arp, $path="ecat_arp_info", $policy=log_policy_ecat_arp]);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88a4, PacketAnalyzer::ANALYZER_ETHERCAT);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERCAT, 0x0800, PacketAnalyzer::ANALYZER_IP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERCAT, 0x0806, PacketAnalyzer::ANALYZER_ARP);
    
}

###############################################################################################
############### Defines logging of ecat_registers event -> ecat_registers.log  ################
###############################################################################################
event ecat_registers(mac_src: string, mac_dst: string, slave_addr: count, reg_type: count, 
                     reg_addr: count, data_cmd: count, data: string)
    {
    local info: ECAT_REGISTER;
    info$ts  = network_time();
    info$srcmac = mac_src;
    info$dstmac  = mac_dst;
    info$Slave_Addr = fmt("0x%02x", slave_addr);
    info$Register_Type = Ecat_Registers[reg_type];
    info$Register_Addr = fmt("0x%02x", reg_addr);
	info$Command = Ecat_Cmd[data_cmd];
    info$data = data;
    
    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_REGISTERS, info);
    }  

###############################################################################################
############# Defines logging of ecat_log_address event -> ecat_log_address.log  ##############
###############################################################################################
event ecat_log_address(mac_src: string, mac_dst: string, data_len: count, data_cmd: count, 
                        data_addr: string, data: string)
    {
    local info: ECAT_LOG_ADDR;
    info$ts  = network_time();
    info$srcmac = mac_src;
    info$dstmac  = mac_dst;
    info$Log_Addr = data_addr;
    info$Length = data_len;
	info$Command = Ecat_Cmd[data_cmd];
    info$data = data;
    
    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_ADDRESS, info);
    }  

###############################################################################################
################# Defines logging of ecat_device event -> ecat_dev_info.log  ##################
###############################################################################################
event ecat_device(SlaveId: count, Revision: count, Type: count, Build: count, FmmuCnt: count, 
                   SmCnt: count, Ports: count, Dpram: count, Features: count)
    {
    local info: ECAT_DEV_INFO;
    info$ts  = network_time();
    info$slave_id = fmt("0x%02x", SlaveId);
    info$revision  = fmt("0x%02x", Revision);
    info$dev_type = fmt("0x%02x", Type);
    info$build = fmt("0x%02x", Build);
    info$fmmucnt = fmt("0x%02x", FmmuCnt);
    info$smcount = fmt("0x%02x", SmCnt);
    info$ports = fmt("0x%02x", Ports);
    info$dpram = fmt("0x%02x", Dpram);
    info$features = fmt("0x%02x", Features);
    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_DEV_INFO, info);
    }

###############################################################################################
################## Defines logging of ecat_AoE event -> ecat_aoe_info.log  ####################
###############################################################################################
event ecat_AoE(targetid: string, senderid: string, targetport: count, senderport: count, 
                cmd: count, stateflags: count, req_res: string)
    {
    local info: ECAT_AOE_INFO;
    info$ts  = network_time();
    info$targetid = targetid;
    info$targetport  = fmt("0x%02x", targetport);
    info$senderid = senderid;
    info$senderport = fmt("0x%02x", senderport);
    info$cmd = Ecat_AoE_Cmd[cmd];
    info$stateflags = fmt("0x%02x", stateflags);
    info$data = req_res;

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_AOE_INFO, info);
    }

###############################################################################################
################## Defines logging of ecat_CoE event -> ecat_coe_info.log  ####################
###############################################################################################
event ecat_CoE(number: count, Type: count, req_resp: count, index: count, subindex: count, 
                dataoffset: count)
    {
    local info: ECAT_COE_INFO;
    info$ts  = network_time();

    info$number  = fmt("0x%02x", number);
    info$Type  = fmt("0x%02x", Type);
    info$req_resp  = fmt("0x%02x", req_resp);
    info$index  = fmt("0x%02x", index);
    info$subindex  = fmt("0x%02x", subindex);
    info$dataoffset  = fmt("0x%02x", dataoffset);

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_COE_INFO, info);
    }

###############################################################################################
################## Defines logging of ecat_FoE event -> ecat_foe_info.log  ####################
###############################################################################################
event ecat_FoE(opCode: count, reserved: count, packet_num: count, error_code: count, filename: 
                string, data: string)
    {
    local info: ECAT_FOE_INFO;
    info$ts  = network_time();

    info$opCode  = fmt("0x%02x", opCode);
    info$reserved  = fmt("0x%02x", reserved);
    info$packet_num  = fmt("0x%02x", packet_num);
    info$error_code  = fmt("0x%02x", error_code);
    info$filename  = filename;
    info$data  = data;

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_FOE_INFO, info);        
    }

###############################################################################################
################## Defines logging of ecat_SoE event -> ecat_soe_info.log  ####################
###############################################################################################
event ecat_SoE(opCode: count, incomplete: count, error: count, drive_num: count, 
                element_flags: count, index: count)
    {
    local info: ECAT_SOE_INFO;
    info$ts  = network_time();

    info$opCode  = fmt("0x%02x", opCode);
    info$incomplete  = fmt("0x%02x", incomplete);
    info$error  = fmt("0x%02x", error);
    info$drive_num  = fmt("0x%02x", drive_num);
    info$element_flags  = fmt("0x%02x", element_flags);
    info$index  = fmt("0x%02x", index);

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_SOE_INFO, info);        
    }

###############################################################################################
################ Defines logging of ecat_arp_info event -> ecat_arp_info.log  #################
###############################################################################################
event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    local info: ECAT_ARP_INFO;
    info$ts  = network_time();
    info$arp_type   = "Request";
    info$mac_src    = mac_src;
    info$mac_dst    = mac_dst;
    info$SPA        = SPA;
    info$SHA        = SHA;
    info$TPA        = TPA;
    info$THA        = THA;

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_ARP_INFO, info); 
    }

###############################################################################################
################ Defines logging of ecat_arp_info event -> ecat_arp_info.log  #################
###############################################################################################
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    local info: ECAT_ARP_INFO;
    info$ts  = network_time();
    info$arp_type   = "Reply";
    info$mac_src    = mac_src;
    info$mac_dst    = mac_dst;
    info$SPA        = SPA;
    info$SHA        = SHA;
    info$TPA        = TPA;
    info$THA        = THA;

    Log::write(PacketAnalyzer::ECAT::LOG_ECAT_ARP_INFO, info); 
    }