//"Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved."
// ECAT.h
//
// ECAT - Defines packet ECATAnalyzer class for ethercat packet analysis through
//        zeek. 
//
// Author:  Devin Vollmer
// Contact: devin.vollmer@inl.gov


#pragma once

#include <packet_analysis/Analyzer.h>
#include <packet_analysis/Component.h>
#include <sys/socket.h>
#pragma once

#include <net/if_arp.h>
#define max_datagram_amount 15
#define max_foe_data 512

namespace zeek::packet_analysis::ETHERCAT {

    typedef struct {
        uint8_t cmd;
        uint8_t index; /**< Index (set by master */
        uint8_t mailbox_type;
        uint8_t last_indicator;
        uint8_t data[1508]; /**< Datagram payload. */
        uint16_t length;
        uint16_t interrupt;
        uint16_t working_counter; /**< Working counter. */
        uint16_t slave_addr;
        uint16_t off_addr; // actual location of register address
        uint16_t off_addr_name;
        uint8_t address[4]; /**< Recipient address. */
    } ecat_datagram;

    typedef struct {
        uint8_t revision; 
        uint8_t type;
        uint8_t fmmu_cnt;
        uint8_t sm_cnt;
        uint8_t ports;
        uint8_t dpram;
        uint16_t features;
        uint16_t build;
    } ecat_device_info;

    typedef struct {
        uint16_t length;
        uint16_t address;
        uint8_t priority;
        uint8_t type;
        uint8_t counter;
    } ecat_mailbox_header;

    typedef struct {
        uint8_t targetid[6];
        uint8_t senderid[6];
        uint8_t req_res[200];
        uint8_t counter;
        uint16_t cmd;
        uint16_t targetport;
        uint16_t senderport;
        uint16_t stateflags;
        uint32_t cbdata;
        uint32_t errorcode;
        uint32_t invokeid;
    } ecat_mailbox_aoe;

    typedef struct {
        uint16_t length;
        uint16_t address;
        uint8_t priority;
        uint8_t type;
        uint8_t counter;
    } ecat_mailbox_eoe;

    typedef struct {
        uint32_t data_offset;
        uint16_t number;
        uint16_t type;
        uint16_t index;
        uint8_t subindex;
        uint8_t req_resp;
    } ecat_mailbox_coe;

    // Need more information on these last three mailbox's
    // FOE, SOE, VOE
    typedef struct {
        uint32_t password;
        uint32_t packet_num;
        uint32_t error_code;
        uint8_t opCode;
        uint8_t reserved;
        uint8_t filename[max_foe_data];
        uint8_t data[max_foe_data];
        uint8_t error_txt[max_foe_data];
    } ecat_mailbox_foe;

    // header structure found in open source documents ros.org
    // no pcap found to verify how to parse this information
    typedef struct {
        uint16_t index;
        uint8_t opCode; 
        uint8_t incomplete;
        uint8_t error;
        uint8_t drive_num;
        uint8_t element_flags;
    } ecat_mailbox_soe;

    // VoE is Vendor specific data
    // typedef struct {
    //     uint16_t length;
    //     uint16_t address;
    //     uint8_t priority;
    //     uint8_t type;
    //     uint8_t counter;
    // } Ecat_Mailbox_VOE;

    typedef struct 
    {
        ecat_mailbox_header header;
        ecat_mailbox_aoe aoe;
        ecat_mailbox_eoe eoe;
        ecat_mailbox_coe coe;
        ecat_mailbox_foe foe;
        ecat_mailbox_soe soe;
       // Ecat_Mailbox_VOE VOE;
    } ecat_mailbox;

    class ECATAnalyzer : public Analyzer {
    public:
        ECATAnalyzer();
        ~ECATAnalyzer() override = default;

        void Initialize() override;

        bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

        static zeek::packet_analysis::AnalyzerPtr Instantiate()
            {
            return std::make_shared<ECATAnalyzer>();
            }

    private:
        uint16_t GetLengthLastInd(uint16_t counter, const uint8_t* data, uint16_t datagram_pos);
        uint16_t GetSlaveOffsetAddr(uint16_t counter, const uint8_t* data, uint16_t datagram_pos);
        uint16_t OffsetAddressParse(uint16_t counter, const uint8_t* data, uint16_t datagram_pos, uint16_t offsetaddress, uint16_t length);
        void EcatMailboxParse(uint16_t length, const uint8_t* data, uint16_t position);
        zeek::AddrValPtr ToAddrVal(const void* addr);
        zeek::StringValPtr ToEthAddrStr(const u_char* addr);
        zeek::StringValPtr HexToString(const u_char* data, uint16_t len);
    };

}
