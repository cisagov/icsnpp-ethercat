//"Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved."
// ECAT.h
//
// ECAT - Defines packet ECATAnalyzer class for ethercat packet analysis through
//        zeek.
//
// Author:  Devin Vollmer
// Contact: devin.vollmer@inl.gov


#pragma once

#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include <sys/socket.h>
#pragma once

#include <net/if_arp.h>
#define HEADER_LENGTH 2
#define MAX_DATAGRAM_COUNT 15
#define DATAGRAM_HEADER_LENGTH 10
#define DATAGRAM_TRAILER_LENGTH 2
#define MAX_DATA_SIZE 2047 // 16-bit field in the spec, but limited to 11 bits by the protocol itself...going with 11-bit size
#define MAX_FOE_DATA_SIZE 512
#define DEVICE_INFO_SIZE 10
#define MAILBOX_HEADER_SIZE 6
#define AOE_HEADER_SIZE 32
#define AOE_ID_LENGTH 6
#define AOE_PORT_LENGTH 2
#define EOE_HEADER_SIZE 18
#define COE_HEADER_SIZE 10
#define FOE_HEADER_SIZE 14
#define SOE_HEADER_SIZE 7

namespace zeek::packet_analysis::ETHERCAT {

    typedef struct {
        uint8_t cmd;
        uint8_t index; /**< Index (set by master */
        uint8_t mailbox_type;
        uint8_t last_indicator;
        uint8_t data[MAX_DATA_SIZE]; /**< Datagram payload. */
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
        uint8_t req_res[MAX_DATA_SIZE];
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
        uint8_t filename[MAX_FOE_DATA_SIZE];
        uint8_t data[MAX_FOE_DATA_SIZE];
        uint8_t error_txt[MAX_FOE_DATA_SIZE];
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
        bool parseMessageHeader(const uint8_t* data, size_t length, uint16_t &messageLength, bool &reserveBit, uint8_t &messageType);
        bool parseDatagram(const uint8_t* data, size_t length, uint8_t currentIndex, uint16_t &dataProcessed);
        bool parseDatagramHeader(const uint8_t* data, size_t length, uint8_t currentIndex);
        bool parseDatagramBody(const uint8_t* data, size_t length, uint8_t currentIndex, uint16_t &dataProcessed, bool &failedInFurtherProcessing);
        bool furtherProcessDatagramBody(uint8_t currentIndex);
        bool processDevTypeData(uint8_t currentIndex);
        bool processPDRAMData(uint8_t currentIndex);
        bool parseMailbox(uint8_t currentIndex);
        bool parseAOE(uint8_t currentIndex);
        bool parseEOE(uint8_t currentIndex);
        bool parseCOE(uint8_t currentIndex);
        bool parseFOE(uint8_t currentIndex);
        bool parseSOE(uint8_t currentIndex);
        bool parseDatagramTrailer(const uint8_t* data, size_t length, uint8_t currentIndex);
        bool commandUsesRegularAddress(uint8_t command);
        uint16_t determineOffsetName(uint16_t offsetAddress);
        zeek::AddrValPtr ToAddrVal(const void* addr);
        zeek::StringValPtr ToEthAddrStr(const u_char* addr);
        zeek::StringValPtr HexToString(const u_char* data, uint16_t len);
    };

}
