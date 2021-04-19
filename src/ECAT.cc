// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
// ECAT.cc
//
// ECAT - Defines packet analysis functions for parsing ethercat packets.
//
// Author:  Devin Vollmer
// Contact: devin.vollmer@inl.gov


#include "ECAT.h"
#include "ECAT_ENUMS.h"
#include "Event.h"
#include <stdio.h>
#include <stdlib.h>
#include "events.bif.h"

#include "zeek-config.h"
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif

using namespace zeek::packet_analysis::ETHERCAT;

ecat_datagram ec_datagram[max_datagram_amount];
ecat_device_info ec_devinfo;
ecat_mailbox ec_mailbox;

ECATAnalyzer::ECATAnalyzer()
    : zeek::packet_analysis::Analyzer("ETHERCAT")
    {
    }

void ECATAnalyzer::Initialize()
    {
    Analyzer::Initialize(); 
    }

// ----------------------------------ECATAnalyzer AnalyzePacket------------------------------------
// Message Description:
//      Main Packet Analyzer for Ecat traffic
// Message Format:
//      - len:                   Length of data passed to analyzer
//      - data:                  Data to be analyzed
//      - packet:                Packet information from parent analyzer(ie. Ethernet analyzer)
// Protocol Parsing:    
//      Parses data according to pack
//      
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
    {
        uint16_t datagram_cnt = 0;
        uint16_t data_count = 0;
        //packet->l3_proto = L3_ECAT;

        // EtherCat message header is 2 bytes at beginning of packet
        uint16_t msg_header = (data[1] << 8) + data[0];

        auto msg_len = msg_header & (0x07FF);
        auto Msg_Ecat_Cmd = (msg_header & (0xF000)) >> 12;

        const u_char* src = packet->l2_src;
        const u_char* dst = packet->l2_dst;

        memset(ec_datagram,0,sizeof(ec_datagram));

        // check length before parsing
        if( msg_len )
            {
            do
                {
                ec_datagram[datagram_cnt].cmd = data[2+data_count];
                data_count += 1;

                ec_datagram[datagram_cnt].index = data[2+data_count];
                data_count += 1;

                ec_datagram[datagram_cnt].off_addr = 0xFF;
                ec_datagram[datagram_cnt].address[0] = 0xFF;
                ec_datagram[datagram_cnt].address[1] = 0xFF;
                ec_datagram[datagram_cnt].address[2] = 0xFF;
                ec_datagram[datagram_cnt].address[3] = 0xFF;

                switch( ec_datagram[datagram_cnt].cmd )
                    {
                    case ecat_datagram_none:
                        data_count = GetSlaveOffsetAddr(data_count, data, datagram_cnt);                    
                        data_count = GetLengthLastInd(data_count, data, datagram_cnt);

                        break;

                    case ecat_datagram_aprd:
                    case ecat_datagram_apwr:
                    case ecat_datagram_aprw:
                    case ecat_datagram_fprd:
                    case ecat_datagram_fpwr:
                    case ecat_datagram_fprw:
                    case ecat_datagram_brd:
                    case ecat_datagram_bwr:
                    case ecat_datagram_brw:
                    case ecat_datagram_armw:
                    case ecat_datagram_frmw:
                        data_count = GetSlaveOffsetAddr(data_count, data, datagram_cnt);                    
                        data_count = GetLengthLastInd(data_count, data, datagram_cnt);
                        data_count = OffsetAddressParse(data_count, ec_datagram[datagram_cnt].data, datagram_cnt, 
                                                        ec_datagram[datagram_cnt].off_addr, ec_datagram[datagram_cnt].length);
                        break;

                    case ecat_datagram_lrd:
                    case ecat_datagram_lwr:
                    case ecat_datagram_lrw:
                        if( (msg_len - data_count) >= 4)
                            {
                            memcpy(ec_datagram[datagram_cnt].address, data + (2 + data_count), 4);
                            }

                        data_count += 4;

                        data_count = GetLengthLastInd(data_count, data, datagram_cnt);

                        break;
                    }

                auto cmd = ec_datagram[datagram_cnt].cmd;
                auto off_type = ec_datagram[datagram_cnt].off_addr_name;
                auto off_addr = ec_datagram[datagram_cnt].off_addr;
                auto slv = ec_datagram[datagram_cnt].slave_addr;
                auto length = ec_datagram[datagram_cnt].length;


                // Set event bassed off of address or offset address. Will possibly change this to datagram type
                // logs in future. Doing datagram type logs will allow for further depth of parsing capabilities. 
                if( ec_datagram[datagram_cnt].address[0] != 0xff && 
                    ec_datagram[datagram_cnt].address[2] != 0xff )
                    {
                    // make sure event exists in script land
                    if( ecat_log_address )
                        {
                        event_mgr.Enqueue(ecat_log_address, ToEthAddrStr(src), ToEthAddrStr(dst), val_mgr->Count(length), 
                                          val_mgr->Count(cmd), HexToString(ec_datagram[datagram_cnt].address,4), 
                                          HexToString(ec_datagram[datagram_cnt].data, ec_datagram[datagram_cnt].length));
                        }
                    }
                else if( ec_datagram[datagram_cnt].off_addr != 0xFF )
                    {
                    // make sure event exists in script land
                    if( ecat_registers )
                        {
                        event_mgr.Enqueue(ecat_registers, ToEthAddrStr(src), ToEthAddrStr(dst), val_mgr->Count(slv),
                                          val_mgr->Count(off_type), val_mgr->Count(off_addr), val_mgr->Count(cmd), 
                                          HexToString(ec_datagram[datagram_cnt].data, ec_datagram[datagram_cnt].length));
                        }
                    }

                datagram_cnt++;

                }while( ec_datagram[datagram_cnt - 1].last_indicator );
            }
        return true;
    }

// -------------------------------ECATAnalyzer GetLengthLastInd----------------------------------
// Message Description:
//      Parses length data and last frame indicator to determine when
//      to stop parsing datagrams.
// Message Format:
//      - counter:               Position in data array to pull data from
//      - data:                  Data to be analyzed
//      - datagram_pos:          Position in ecdatagram array
// Return:
//      Returns position in data array
// Protocol Parsing:    
//      Parses data according to pack
//
//      Ethercat length and Last indicator sent in 2 bytes 
//      length bits      .... .000 0000 0000
//      Reserved         ..00 0... .... ....
//      Round Trip       .0.. .... .... ....
//      Last Indicator   0... .... .... ....
// ------------------------------------------------------------------------------------------------
uint16_t ECATAnalyzer::GetLengthLastInd(uint16_t counter, const uint8_t* data, uint16_t datagram_pos)
    {
    ec_datagram[datagram_pos].length = ((data[2 + (counter + 1)] << 8) + data[2 + counter]) & (0x07ff);
    ec_datagram[datagram_pos].last_indicator = (((data[2 + (counter + 1)] << 8) + data[2 + counter]) & (0xF000)) >> 12;
    counter += 2;

    ec_datagram[datagram_pos].interrupt = ((data[2 + (counter + 1)] << 8) + data[2 + counter]);
    counter += 2;

    if( ec_datagram[datagram_pos].length > 0 )
        {
        memcpy(ec_datagram[datagram_pos].data, data+(2 + counter), ec_datagram[datagram_pos].length);
        counter += ec_datagram[datagram_pos].length;
        }
    ec_datagram[datagram_pos].working_counter = ((data[2 + (counter + 1)] << 8) + data[2 + counter]);
    counter+=2;

    return counter;
    }

// -------------------------------ECATAnalyzer APRD----------------------------------
// Message Description:
//      Auto Increment Physical Read.
// Function Input:
//      - counter:               Position in data array to pull data from
//      - data:                  Data to be analyzed
//      - datagram_pos:          Position in ecdatagram array
// Return:
//      - counter:               Returns position in data array
// Protocol Parsing:    
//      Parses data according to pack
// ----------------------------------------------------------------------------------
uint16_t ECATAnalyzer::GetSlaveOffsetAddr(uint16_t counter, const uint8_t* data, uint16_t datagram_pos)
    {
    ec_datagram[datagram_pos].slave_addr = (data[2 + (counter + 1)] << 8) + data[2 + counter];
    counter += 2;
    ec_datagram[datagram_pos].off_addr = (data[2 + counter + 1] << 8) + data[2 + counter];
    counter += 2;

    return counter;
    }

// ------------------------ECATAnalyzer OffsetAddressParse---------------------------
// Message Description:
//      Register offset parsing
// Function Input:
//      - counter:               Position in data array to pull data from
//      - data:                  Data to be analyzed
//      - datagram_pos:          Position in ecdatagram array
//      - offsetaddress:         Register address being accessed
//      - length                 Data length containing register values to be rd/wr
// Return:
//      - counter:               Returns position in data array
// Protocol Parsing:    
//      Parses data according to register information in Ecat pdf document
// ----------------------------------------------------------------------------------
uint16_t ECATAnalyzer::OffsetAddressParse(uint16_t counter, const uint8_t* data, uint16_t datagram_pos, 
                                          uint16_t offsetaddress, uint16_t length)
    {

    if( offsetaddress >= dev_type && offsetaddress < revision )
        {
        ec_datagram[datagram_pos].off_addr_name = dev_type;
        if( length == 10 )
            {
            ec_devinfo.revision = data[0];
            ec_devinfo.type     = data[1];
            ec_devinfo.build    = (data[3] << 8) + data[2];
            ec_devinfo.fmmu_cnt = data[4];
            ec_devinfo.sm_cnt   = data[5];
            ec_devinfo.dpram    = data[6];
            ec_devinfo.ports    = data[7];
            ec_devinfo.features = (data[9] << 8) + data[8];
            }

        auto slv        = ec_datagram[datagram_pos].slave_addr;
        auto revision   = ec_devinfo.revision;
        auto type       = ec_devinfo.type;
        auto build      = ec_devinfo.build;
        auto fmmu_cnt   = ec_devinfo.fmmu_cnt;
        auto sm_cnt     = ec_devinfo.sm_cnt;
        auto ports      = ec_devinfo.ports;
        auto dpram      = ec_devinfo.dpram;
        auto features   = ec_devinfo.features;

        if( ecat_device)
            {
            event_mgr.Enqueue(ecat_device, val_mgr->Count(slv), val_mgr->Count(revision), val_mgr->Count(type), 
                          val_mgr->Count(build), val_mgr->Count(fmmu_cnt), val_mgr->Count(sm_cnt), 
                          val_mgr->Count(ports), val_mgr->Count(dpram), val_mgr->Count(features));
            }
        }

    if( offsetaddress >= revision && offsetaddress < build )
        ec_datagram[datagram_pos].off_addr_name = revision;
    
    if( offsetaddress >= build && offsetaddress < fmmuspt )
        ec_datagram[datagram_pos].off_addr_name = build;
    
    if( offsetaddress >= fmmuspt && offsetaddress < sync_managers )
        ec_datagram[datagram_pos].off_addr_name = fmmuspt;
    
    if( offsetaddress >= sync_managers && offsetaddress < ram_size )
        ec_datagram[datagram_pos].off_addr_name = sync_managers;
    
    if( offsetaddress >= ram_size && offsetaddress < port_descriptor )
        ec_datagram[datagram_pos].off_addr_name = ram_size;
    
    if( offsetaddress >= port_descriptor && offsetaddress < esc_features )
        ec_datagram[datagram_pos].off_addr_name = port_descriptor;
    
    if( offsetaddress >= esc_features && offsetaddress < cs_addr )
        ec_datagram[datagram_pos].off_addr_name = esc_features;
    
    if( offsetaddress >= cs_addr && offsetaddress < cs_alias )
        ec_datagram[datagram_pos].off_addr_name = cs_addr;
    
    if( offsetaddress >= cs_alias && offsetaddress < reg_write_en )
        ec_datagram[datagram_pos].off_addr_name = cs_alias;
    
    if( offsetaddress >= reg_write_en && offsetaddress < reg_write_prot )
        ec_datagram[datagram_pos].off_addr_name = reg_write_en;
    
    if( offsetaddress >= reg_write_prot && offsetaddress < esc_write_en )
        ec_datagram[datagram_pos].off_addr_name = reg_write_prot;
    
    if( offsetaddress >= esc_write_en && offsetaddress < reg_write_prot )
        ec_datagram[datagram_pos].off_addr_name = esc_write_en;
    
    if( offsetaddress >= reg_write_prot && offsetaddress < esc_rst_ecat )
        ec_datagram[datagram_pos].off_addr_name = reg_write_prot;
    
    if( offsetaddress >= esc_rst_ecat && offsetaddress < esc_rst_pdi )
        ec_datagram[datagram_pos].off_addr_name = esc_rst_ecat;
    
    if( offsetaddress >= esc_rst_pdi && offsetaddress < esc_dl_ctl )
        ec_datagram[datagram_pos].off_addr_name = esc_rst_pdi;

    if( offsetaddress >= esc_dl_ctl && offsetaddress < phy_rd_wr_offs )
        ec_datagram[datagram_pos].off_addr_name = esc_dl_ctl;
    
    if( offsetaddress >= phy_rd_wr_offs && offsetaddress < esc_dl_stat )
        ec_datagram[datagram_pos].off_addr_name = phy_rd_wr_offs;
    
    if( offsetaddress >= esc_dl_stat && offsetaddress < al_ctrl )
        ec_datagram[datagram_pos].off_addr_name = esc_dl_stat;
    
    if( offsetaddress >= al_ctrl && offsetaddress < al_stat )
        ec_datagram[datagram_pos].off_addr_name = al_ctrl;
    
    if( offsetaddress >= al_stat && offsetaddress < al_stat_code )
        ec_datagram[datagram_pos].off_addr_name = al_stat;
    
    if( offsetaddress >= al_stat_code && offsetaddress < run_led_ovrd )
        ec_datagram[datagram_pos].off_addr_name = al_stat_code;
    
    if( offsetaddress >= run_led_ovrd && offsetaddress < err_led_ovrd )
        ec_datagram[datagram_pos].off_addr_name = run_led_ovrd;
    
    if( offsetaddress >= err_led_ovrd && offsetaddress < pdi_ctrl )
        ec_datagram[datagram_pos].off_addr_name = err_led_ovrd;
    
    if( offsetaddress >= pdi_ctrl && offsetaddress < esc_conf )
        ec_datagram[datagram_pos].off_addr_name = pdi_ctrl;
    
    if( offsetaddress >= esc_conf && offsetaddress < pdi_info )
        ec_datagram[datagram_pos].off_addr_name = esc_conf;
    
    if( offsetaddress >= pdi_info && offsetaddress < pdi_conf )
        ec_datagram[datagram_pos].off_addr_name = pdi_info;
    
    if( offsetaddress >= pdi_conf && offsetaddress < pdi_onchip_conf )
        ec_datagram[datagram_pos].off_addr_name = pdi_conf;

    if( offsetaddress >= pdi_onchip_conf && offsetaddress < sync_latc_pdi )
        ec_datagram[datagram_pos].off_addr_name = pdi_onchip_conf;
    
    if( offsetaddress >= sync_latc_pdi && offsetaddress < ecat_ev_msk )
        ec_datagram[datagram_pos].off_addr_name = sync_latc_pdi;
    
    if( offsetaddress >= ecat_ev_msk && offsetaddress < pdi_al_ev_msk )
        ec_datagram[datagram_pos].off_addr_name = ecat_ev_msk;
    
    if( offsetaddress >= pdi_al_ev_msk && offsetaddress < ecat_ev_req )
        ec_datagram[datagram_pos].off_addr_name = pdi_al_ev_msk;
    
    if( offsetaddress >= ecat_ev_req && offsetaddress < al_ev_req )
        ec_datagram[datagram_pos].off_addr_name = ecat_ev_req;
    
    if( offsetaddress >= al_ev_req && offsetaddress < rx_err_cnt )
        ec_datagram[datagram_pos].off_addr_name = al_ev_req;
    
    if( offsetaddress >= rx_err_cnt && offsetaddress < fwd_rx_err_cnt )
        ec_datagram[datagram_pos].off_addr_name = rx_err_cnt;
    
    if( offsetaddress >= fwd_rx_err_cnt && offsetaddress < ecat_proc_err_cnt )
        ec_datagram[datagram_pos].off_addr_name = fwd_rx_err_cnt;
    
    if( offsetaddress >= ecat_proc_err_cnt && offsetaddress < pdi_err_cnt )
        ec_datagram[datagram_pos].off_addr_name = ecat_proc_err_cnt;
    
    if( offsetaddress >= pdi_err_cnt && offsetaddress < pdi_err_code )
        ec_datagram[datagram_pos].off_addr_name = pdi_err_cnt;
    
    if( offsetaddress >= pdi_err_code && offsetaddress < llc )
        ec_datagram[datagram_pos].off_addr_name = pdi_err_code;
    
    if( offsetaddress >= llc && offsetaddress < wtd_div )
        ec_datagram[datagram_pos].off_addr_name = llc;
    
    if( offsetaddress >= wtd_div && offsetaddress < wtd_time_pdi )
        ec_datagram[datagram_pos].off_addr_name = wtd_div;
    
    if( offsetaddress >= wtd_time_pdi && offsetaddress < wtd_time_proc_data )
        ec_datagram[datagram_pos].off_addr_name = wtd_time_pdi;
    
    if( offsetaddress >= wtd_time_proc_data && offsetaddress < wtd_stat_proc_data )
        ec_datagram[datagram_pos].off_addr_name = wtd_time_proc_data;
    
    if( offsetaddress >= wtd_stat_proc_data && offsetaddress < wtd_cnt_proc_data )
        ec_datagram[datagram_pos].off_addr_name = wtd_stat_proc_data;
    
    if( offsetaddress >= wtd_cnt_proc_data && offsetaddress < wtd_cnt_pdi )
        ec_datagram[datagram_pos].off_addr_name = wtd_cnt_proc_data;
    
    if( offsetaddress >= wtd_cnt_pdi && offsetaddress < sii_eeprom_intr )
        ec_datagram[datagram_pos].off_addr_name = wtd_cnt_pdi;
    
    if( offsetaddress >= sii_eeprom_intr && offsetaddress < mii_mang_intr )
        ec_datagram[datagram_pos].off_addr_name = sii_eeprom_intr;
    
    if( offsetaddress >= mii_mang_intr && offsetaddress < fmmu )
        ec_datagram[datagram_pos].off_addr_name = mii_mang_intr;
    
    if( offsetaddress >= fmmu && offsetaddress < sync_manager )
        ec_datagram[datagram_pos].off_addr_name = fmmu;
    
    if( offsetaddress >= sync_manager && offsetaddress < dist_clk )
        ec_datagram[datagram_pos].off_addr_name = sync_manager;
    
    if( offsetaddress >= dist_clk && offsetaddress < esc_specf_reg )
        ec_datagram[datagram_pos].off_addr_name = dist_clk;
    
    if( offsetaddress >= esc_specf_reg && offsetaddress < dig_io_data )
        ec_datagram[datagram_pos].off_addr_name = esc_specf_reg;

    if( offsetaddress >= dig_io_data && offsetaddress < gp_out_data )
        ec_datagram[datagram_pos].off_addr_name = dig_io_data;

    if( offsetaddress >= gp_out_data && offsetaddress < gp_in )
        ec_datagram[datagram_pos].off_addr_name = gp_out_data;

    if( offsetaddress >= gp_in && offsetaddress < usr_ram )
        ec_datagram[datagram_pos].off_addr_name = gp_in;

    if( offsetaddress >= usr_ram && offsetaddress < pd_ram )
        ec_datagram[datagram_pos].off_addr_name = usr_ram;
   
    if( offsetaddress >= pd_ram )
        {
        int temp = 0;
        ec_datagram[datagram_pos].off_addr_name = pd_ram;

        ec_mailbox.header.length = (data[1] << 8) + data[0];

        if( (ec_datagram[datagram_pos].length > 1) && 
            (ec_mailbox.header.length > 0) )
            {
            ec_mailbox.header.address = (data[3] << 8) + data[2];
            ec_mailbox.header.priority = data[4] & 0x03;
            ec_mailbox.header.type = data[5] & 0x0F;
            ec_mailbox.header.counter = (data[5] & 0xF0) >> 4;
            
            EcatMailboxParse(ec_mailbox.header.length+6, data, 6);

            }

        }
    return counter;
    }

// ------------------------ECATAnalyzer EcatMailboxParse---------------------------
// Message Description:
//      EtherCat Mailbox parseing
// Function Input:
//      - length                 Data length containing register values to be rd/wr
//      - data:                  Data to be analyzed
//      - position:              Position offset to data array
//      - offsetaddress:         Register address being accessed
// Return:
//      - void
// Protocol Parsing:    
//      Parses data according to ec_mailbox header type 
// ----------------------------------------------------------------------------------
void ECATAnalyzer::EcatMailboxParse(uint16_t length, const uint8_t* data, uint16_t position)
    {
    int i = 0;
    char buf[100];

    if( ec_mailbox.header.type == ecat_mbx_none )
        {
            // NOP
        }

    // ADS over EtherCAT 
    if( ec_mailbox.header.type ==  ecat_mbx_aoe )
        {
        for( i = 5; i >= 0; i-- )
            {
            ec_mailbox.aoe.targetid[i] = data[position];
            position += 1;
            }

        ec_mailbox.aoe.targetport = (data[position+1] << 8) + data[position];
        position += 2;

        for( i = 5; i >= 0; i-- )
            {
            ec_mailbox.aoe.senderid[i] = data[position];
            position += 1;
            }

        ec_mailbox.aoe.senderport = (data[position + 1] << 8) + data[position];
        position += 2;

        ec_mailbox.aoe.cmd = (data[position + 1] << 8) + data[position];
        position += 2;

        ec_mailbox.aoe.stateflags = (data[position + 1] << 8) + data[position];
        position += 2;

        ec_mailbox.aoe.cbdata = (data[position + 3] << 24) + (data[position+2] << 16) + 
                                (data[position + 1] << 8) + data[position];
        position += 4;

        ec_mailbox.aoe.errorcode = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                   (data[position + 1] << 8) + data[position];
        position += 4;

        ec_mailbox.aoe.invokeid = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                  (data[position + 1] << 8) + data[position];
        position += 4;

        memcpy(ec_mailbox.aoe.req_res, data+position, (length - position));
 
        auto t_port = ec_mailbox.aoe.targetport;
        auto s_port = ec_mailbox.aoe.senderport;
        auto cmmd = ec_mailbox.aoe.cmd;
        auto stateflags = ec_mailbox.aoe.stateflags;

        // Check if event exists in scriptland
        if( ecat_AoE )
            {
            // Set AoE event to log to AOE log
            event_mgr.Enqueue(ecat_AoE, ToEthAddrStr(ec_mailbox.aoe.targetid), ToEthAddrStr(ec_mailbox.aoe.senderid), 
                          val_mgr->Count(t_port), val_mgr->Count(s_port), val_mgr->Count(cmmd), 
                          val_mgr->Count(stateflags), HexToString(ec_mailbox.aoe.req_res, (length - position)));
            }
        }

    
    // Ethernet over Ethercat
    if( ec_mailbox.header.type == ecat_mbx_eoe )
        {
        Packet tmppacket;

        uint32_t protocol = (data[position + 16] << 8) + data[position + 17];
        
        tmppacket.eth_type = protocol;
        tmppacket.l2_dst = data + (position + 4);  //(Position + 4) is to skip over 4byte ecat EoE header 
        tmppacket.l2_src = data + (position + 10);
        tmppacket.len = length - (position + 4);
        tmppacket.data = data + (position + 4);

        // check for type greater than or equal to IP and forward to next analyzer
        if( tmppacket.eth_type  >= 0x0800)
            {
            ForwardPacket(tmppacket.len, data + (position + 18),
                          &tmppacket, tmppacket.eth_type);
            }
        else
            Weird("Non_IP Protocol Detected", &tmppacket);
        }

    // CAN-open over Ethercat
    if( ec_mailbox.header.type == ecat_mbx_coe )
        {
        ec_mailbox.coe.number = data[position++];
        ec_mailbox.coe.type = (data[position++] & 0xF0 >> 4);
        ec_mailbox.coe.req_resp = data[position++];
        ec_mailbox.coe.index = (data[position + 1] << 8) + data[position];
        position += 2;
        ec_mailbox.coe.subindex = data[position++];
        ec_mailbox.coe.data_offset = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                     (data[position + 1] << 8) + data[position];
        position += 4;

        // create coe event to write data to coe log file
        auto number = ec_mailbox.coe.number;
        auto type = ec_mailbox.coe.type;
        auto req_resp = ec_mailbox.coe.req_resp;
        auto index = ec_mailbox.coe.index;
        auto subindex = ec_mailbox.coe.subindex;
        auto data_offset = ec_mailbox.coe.data_offset;

        // Check if event exists in scriptland
        if( ecat_CoE)
            {
            // set CoE event to log to COE log file
            event_mgr.Enqueue(ecat_CoE, val_mgr->Count(number), val_mgr->Count(type), val_mgr->Count(req_resp), 
                              val_mgr->Count(index), val_mgr->Count(subindex), val_mgr->Count(data_offset));
            }
        }

    //File-Access over EtherCAT 
    if( ec_mailbox.header.type == ecat_mbx_foe )
        {
        ec_mailbox.foe.opCode = data[position++];
        ec_mailbox.foe.reserved = data[position++];
        ec_mailbox.foe.password = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                  (data[position + 1] << 8) + data[position];
        position += 4;

        ec_mailbox.foe.packet_num = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                    (data[position + 1] << 8) + data[position];
        position += 4;

        ec_mailbox.foe.error_code = (data[position + 3] << 24) + (data[position + 2] << 16) + 
                                    (data[position + 1] << 8) + data[position];
        position += 4;

        if( length >= (position + max_foe_data) )
            {
            memcpy(ec_mailbox.foe.filename, data+position, max_foe_data);
            position += max_foe_data;
            }

        if( length >= (position + max_foe_data) )
            {
            memcpy(ec_mailbox.foe.data, data+position, max_foe_data);
            position += max_foe_data;
            }

        if( length >= (position + max_foe_data) )
            {
            memcpy(ec_mailbox.foe.error_txt, data+position, max_foe_data);
            position += max_foe_data;
            }

        auto opCode = ec_mailbox.foe.opCode;
        auto reserved = ec_mailbox.foe.reserved;
        auto packet_num = ec_mailbox.foe.packet_num;
        auto error_code = ec_mailbox.foe.error_code;

        // Check if event exists in scriptland
        if( ecat_FoE )
            {
            // set FoE event to log to FOE log file
            event_mgr.Enqueue(ecat_FoE, val_mgr->Count(opCode), val_mgr->Count(reserved), val_mgr->Count(packet_num), 
                              val_mgr->Count(error_code), HexToString(ec_mailbox.foe.filename, max_foe_data), 
                              HexToString(ec_mailbox.foe.data, max_foe_data));
            }
        }
    
    //Servo-Profile over EtherCAT
    if( ec_mailbox.header.type == ecat_mbx_soe )
        {
        ec_mailbox.soe.opCode = data[position++];
        ec_mailbox.soe.incomplete = data[position++];
        ec_mailbox.soe.error = data[position++];
        ec_mailbox.soe.drive_num = data[position++];
        ec_mailbox.soe.element_flags = data[position++];
        ec_mailbox.soe.index = (data[position + 1] << 8) + data[position];
        position += 2;


        auto opCode = ec_mailbox.soe.opCode;
        auto incomplete = ec_mailbox.soe.incomplete;
        auto error = ec_mailbox.soe.error;
        auto drive_num = ec_mailbox.soe.drive_num;
        auto element_flags = ec_mailbox.soe.element_flags;
        auto index = ec_mailbox.soe.index;

        // Check if event exists in scriptland
        if( ecat_SoE )
            {
            // set SoE event to log to SOE log file
            event_mgr.Enqueue(ecat_SoE, val_mgr->Count(opCode), val_mgr->Count(incomplete), val_mgr->Count(error), 
                              val_mgr->Count(drive_num), val_mgr->Count(element_flags), val_mgr->Count(index));
            }
        
        }
    }


zeek::AddrValPtr ECATAnalyzer::ToAddrVal(const void* addr)
    {
    //Note: We only handle IPv4 addresses.
    return zeek::make_intrusive<zeek::AddrVal>(*(const uint32_t*) addr);
    }

zeek::StringValPtr ECATAnalyzer::ToEthAddrStr(const u_char* addr)
    {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return zeek::make_intrusive<zeek::StringVal>(buf);
    }

zeek::StringValPtr ECATAnalyzer::HexToString(const u_char* data, uint16_t len)
    {
    char buf[0x2000];
    int offset = 0;
    int count = 0;
    if( len)
        {
        for(int i = 0; i < len; i++)
            {
            if( ((data[i] & 0xF0) >> 4) > 0x09)
                buf[count] = (((data[i] & 0xF0) >> 4) - 0x0A) + 0x41;
            else
                buf[count] = ((data[i] & 0xF0) >> 4) + 0x30;

            if( ((data[i] & 0x0F)) > 0x09)
                buf[count+1] = ((data[i] & 0x0F) - 0x0A) + 0x41;
            else
                buf[count+1] = (data[i] & 0x0F) + 0x30;

            count += 2;
            }
        
        buf[count] = 0x00;
        return zeek::make_intrusive<zeek::StringVal>(buf);
        } 
    return NULL;
    }
