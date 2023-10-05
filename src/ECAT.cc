// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
// ECAT.cc
//
// ECAT - Defines packet analysis functions for parsing ethercat packets.
//
// Author:  Devin Vollmer
// Contact: devin.vollmer@inl.gov


#include "ECAT.h"
#include "ECAT_ENUMS.h"
#include "zeek/Event.h"
#include <stdio.h>
#include <stdlib.h>
#include "events.bif.h"

#include "zeek/zeek-config.h"
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

ecat_datagram ec_datagram[MAX_DATAGRAM_COUNT];
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

// Assumption: there is 2 bytes available starting at "data"
uint16_t inline readLittleEndianShort(const uint8_t *data)
{
    return (data[1] << 8) + data[0];
}

// Assumption: there is 2 bytes available starting at "data"
uint16_t inline readBigEndianShort(const uint8_t *data)
{
    return (data[0] << 8) + data[1];
}

// Assumption: there is 4 bytes available starting at "data"
uint32_t inline readLittleEndianInt(const uint8_t *data)
{
    return (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];
}

void inline setAddresses(uint8_t currentIndex, uint32_t addressValue, uint16_t slaveAddress, uint16_t offsetValue)
{
    ec_datagram[currentIndex].address[0] = addressValue & 0xFF;
    ec_datagram[currentIndex].address[1] = (addressValue & 0xFF00) >> 8;
    ec_datagram[currentIndex].address[2] = (addressValue & 0xFF0000) >> 16;
    ec_datagram[currentIndex].address[3] = (addressValue & 0xFF000000) >> 24;
    ec_datagram[currentIndex].slave_addr = slaveAddress;
    ec_datagram[currentIndex].off_addr = offsetValue;
}

// Returns true if currentRegisterAddress <= offsetAddress < nextRegisterAddress
bool inline inDesiredRegisterRange(uint16_t offsetAddress, uint16_t currentRegisterAddress, uint16_t nextRegisterAddress)
{
    return offsetAddress >= currentRegisterAddress && offsetAddress < nextRegisterAddress;
}

// ----------------------------------ECATAnalyzer AnalyzePacket------------------------------------
// Message Description:
//      Main Packet Analyzer for Ecat traffic
// Arguments:
//      - len:                   Length of data passed to analyzer
//      - data:                  Data to be analyzed
//      - packet:                Packet information from parent analyzer(ie. Ethernet analyzer)
// Protocol Parsing:
//      Parses data according to pack
//
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
{
    const u_char* src = packet->l2_src;
    const u_char* dst = packet->l2_dst;
    
    uint16_t messageLength;
    bool reservedBit;
    uint8_t messageType;
    // Verify we have enough data to extract a header
    if(!parseMessageHeader(data, len, messageLength, reservedBit, messageType))
    {
    Weird("Short EtherCAT Packet", packet);
    return false;
    }
    
    if(messageLength + HEADER_LENGTH > len)
    {
        Weird("Message Length and Packet Length Mismatch", packet);
        return false;
    }
    
    uint8_t datagramCount = 0;
    uint16_t dataProcessed = 0;
    const uint8_t *currentDatagramStart = data + HEADER_LENGTH;
    size_t remainingLength = messageLength;
    memset(ec_datagram, 0, sizeof(ec_datagram));
    while(0 < remainingLength)
    {
        uint16_t tempDataProcessed;
        if(!parseDatagram(currentDatagramStart, remainingLength,
                          datagramCount, tempDataProcessed))
        {
            Weird("Bad Packet Length", packet);
            return false;
        }
        currentDatagramStart += tempDataProcessed;
        remainingLength -= tempDataProcessed;
        
        // Log the information
        if(0xFF != ec_datagram[datagramCount].address[0] &&
           0xFF != ec_datagram[datagramCount].address[2])
        {
            if(ecat_log_address)
            {
                event_mgr.Enqueue(ecat_log_address,
                                  ToEthAddrStr(src),
                                  ToEthAddrStr(dst),
                                  val_mgr->Count(ec_datagram[datagramCount].length),
                                  val_mgr->Count(ec_datagram[datagramCount].cmd),
                                  HexToString(ec_datagram[datagramCount].address, 4),
                                  HexToString(ec_datagram[datagramCount].data, ec_datagram[datagramCount].length));
            }
        }
        else if(0xFF != ec_datagram[datagramCount].off_addr)
        {
            if(ecat_registers)
            {
                event_mgr.Enqueue(ecat_registers,
                                  ToEthAddrStr(src),
                                  ToEthAddrStr(dst),
                                  val_mgr->Count(ec_datagram[datagramCount].slave_addr),
                                  val_mgr->Count(ec_datagram[datagramCount].off_addr_name),
                                  val_mgr->Count(ec_datagram[datagramCount].off_addr),
                                  val_mgr->Count(ec_datagram[datagramCount].cmd),
                                  HexToString(ec_datagram[datagramCount].data, ec_datagram[datagramCount].length));
            }
        }
        
        if(0 == ec_datagram[datagramCount++].last_indicator)
        {
            // Last datagram has been parsed
            break;
        }
        
        if(MAX_DATAGRAM_COUNT <= datagramCount)
        {
            Weird("Too many datagrams", packet);
            return false;
        }
    }
    
    if(0 < remainingLength)
    {
        Weird("Packet data remaining", packet);
        return false;
    }
    
    return true;
}

// -------------------------------ECATAnalyzer parseMessageHeader----------------------------------
// Message Description:
//      Parses the two byte EtherCAT Header
// Arguments:
//      - data:                  Data to be analyzed
//      - length:                Length of data
//      - messageLength (out):   Parsed message length
//      - reserveBit (out):      Value of the reserved bit
//      - messageType (out):     Parsed message type
// Return:
//      Returns whether or not there were enough bytes to parse the message header
// Protocol Parsing:
//      Parses data according to pack (note, packed as Little Endian)
//
//      Ethercat length and message type sent in 2 bytes
//      Message Length   .... .xxx xxxx xxxx
//      Reserved         .... 0... .... ....
//      Message Type     xxxx .... .... ....
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::parseMessageHeader(const uint8_t* data, size_t length, uint16_t &messageLength, bool &reserveBit, uint8_t &messageType)
{
    if(HEADER_LENGTH > length)
    {
        return false;
    }
    uint16_t messageHeader = readLittleEndianShort(data);
    messageLength = messageHeader & 0x07FF;
    reserveBit = (messageHeader & 0x0800) >> 11;
    messageType = (messageHeader & 0xF000) >> 12;
    return true;
}

// -------------------------------ECATAnalyzer parseDatagram----------------------------------
// Message Description:
//      Parses the two byte EtherCAT Header
// Arguments:
//      - data:                  Data to be analyzed
//      - length:                Length of data
//      - currentIndex:          Datagram array index to use for storing data
//      - dataProcessed (out):   The number of bytes parsed for the datagram
// Return:
//      Returns whether or not the datagram was parsed correctly
// Protocol Parsing:
//      Parses data according to pack
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::parseDatagram(const uint8_t* data, size_t length, uint8_t currentIndex, uint16_t &dataProcessed)
{
    memset(&ec_devinfo, 0, sizeof(ec_devinfo));
    memset(&ec_mailbox, 0, sizeof(ec_mailbox));
    dataProcessed = 0;
    if(!parseDatagramHeader(data, length, currentIndex))
    {
        return false;
    }
    dataProcessed = DATAGRAM_HEADER_LENGTH;
    uint16_t newDataProcessed;
    bool failedInFurtherProcessing;
    if(!parseDatagramBody(data + dataProcessed, length - dataProcessed, currentIndex, newDataProcessed, failedInFurtherProcessing))
    {
        return false;
    }
    if(failedInFurtherProcessing)
    {
        // TODO: What do we do?
    }
    dataProcessed += newDataProcessed;
    if(!parseDatagramTrailer(data + dataProcessed, length - dataProcessed, currentIndex))
    {
        return false;
    }
    dataProcessed += DATAGRAM_TRAILER_LENGTH;
    return true;
}

// -------------------------------ECATAnalyzer parseMessageHeader----------------------------------
// Message Description:
//      Parses the EtherCAT Datagram Header
// Arguments:
//      - data:                  Data to be analyzed
//      - length:                Length of data
//      - currentIndex:          Datagram array index to use for storing data
// Return:
//      Returns whether or not there were enough bytes to parse the message header
// Protocol Parsing:
//      Parses data according to pack (note, packed as Little Endian)
//
//      Ethercat length and message type sent in 2 bytes
//      Message Length   .... .xxx xxxx xxxx
//      Reserved         ..00 0... .... ....
//      Circulating      .x.. .... .... ....
//      Next             x... .... .... ....
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::parseDatagramHeader(const uint8_t* data, size_t length, uint8_t currentIndex)
{
    if(length < DATAGRAM_HEADER_LENGTH)
    {
        return false;
    }
    // 8-bit Command
    ec_datagram[currentIndex].cmd = data[0];
    // 8-bit Index
    ec_datagram[currentIndex].index = data[1];
    // 32-bit Address/(Slave Address + Offset)
    uint32_t tempAddress = readLittleEndianInt(data+2);
    if(commandUsesRegularAddress(ec_datagram[currentIndex].cmd))
    {
        // 0xFF is used in the old code as a marker for the offset
        setAddresses(currentIndex, tempAddress, 0x00, 0xFF);
    }
    else
    {
        uint16_t slaveAddress = tempAddress & 0xFFFF;
        uint16_t offset = (tempAddress & 0xFFFF0000) >> 16;
        setAddresses(currentIndex, 0xFFFFFFFF, slaveAddress, offset);
        ec_datagram[currentIndex].off_addr_name = determineOffsetName(offset);
    }
    // 16-bit Bitfield
    uint16_t tempBits = readLittleEndianShort(data+6);
    ec_datagram[currentIndex].length = tempBits & 0x07FF;
    uint8_t reservedBits = (tempBits & 0x3800) >> 11;
    uint8_t circulatingBit = (tempBits & 0x4000) >> 14;
    uint8_t hasNextBit = (tempBits & 0x8000) >> 15;
    // TODO: Double check this...this seems to be a bug in the old version where
    // it uses both circulating bits and hasNextBit
    ec_datagram[currentIndex].last_indicator = hasNextBit;
    // 16-bit IRQ
    ec_datagram[currentIndex].interrupt = readLittleEndianShort(data+8);
    return true;
}

// -------------------------------ECATAnalyzer parseDatagramBody----------------------------------
// Message Description:
//      Parses the EtherCAT Datagram Body
// Arguments:
//      - data:                  Data to be analyzed
//      - length:                Length of data
//      - currentIndex:          Datagram array index to use for storing data
//      - dataProcessed (out):   The number of bytes parsed for the datagram
// Return:
//      Returns whether or not there were enough bytes to parse the message trailer
// Protocol Parsing:
//      Parses data according to pack (note, packed as Little Endian)
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::parseDatagramBody(const uint8_t* data, size_t length, uint8_t currentIndex, uint16_t &dataProcessed, bool &failedInFurtherProcessing)
{
    failedInFurtherProcessing = false;
    if(ec_datagram[currentIndex].length > length ||
       ec_datagram[currentIndex].length > MAX_DATA_SIZE)
    {
        return false;
    }
    
    // First copy the data
    memcpy(ec_datagram[currentIndex].data, data, ec_datagram[currentIndex].length);
    dataProcessed = ec_datagram[currentIndex].length;
    
    // Attempt further processing if possible
    switch(ec_datagram[currentIndex].cmd)
    {
        case ecat_datagram_aprd:
            // Intentional Fallthrough
        case ecat_datagram_apwr:
            // Intentional Fallthrough
        case ecat_datagram_aprw:
            // Intentional Fallthrough
        case ecat_datagram_fprd:
            // Intentional Fallthrough
        case ecat_datagram_fpwr:
            // Intentional Fallthrough
        case ecat_datagram_fprw:
            // Intentional Fallthrough
        case ecat_datagram_brd:
            // Intentional Fallthrough
        case ecat_datagram_bwr:
            // Intentional Fallthrough
        case ecat_datagram_brw:
            // Intentional Fallthrough
        case ecat_datagram_armw:
            // Intentional Fallthrough
        case ecat_datagram_frmw:
            failedInFurtherProcessing = !furtherProcessDatagramBody(currentIndex);
            break;
        default:
            // Currently don't know how to process...so leave it as data
            break;
    }
    return true;
}

// -------------------------------ECATAnalyzer furtherProcessDatagramBody----------------------------------
// Message Description:
//      Further process the datagram body if we know how to
// Arguments:
//      - currentIndex:          Datagram array index to use for storing data
// Return:
//      False if there was a problem parsing known data, otherwise true
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::furtherProcessDatagramBody(uint8_t currentIndex)
{
    switch(ec_datagram[currentIndex].off_addr_name)
    {
        case dev_type:
            return processDevTypeData(currentIndex);
        case pd_ram:
            return processPDRAMData(currentIndex);
        default:
            // Don't know how to parse further
            return true;
    }
}

bool ECATAnalyzer::processDevTypeData(uint8_t currentIndex)
{
    if(ec_datagram[currentIndex].length < DEVICE_INFO_SIZE)
    {
        return false;
    }
    
    ec_devinfo.revision = ec_datagram[currentIndex].data[0];
    ec_devinfo.type = ec_datagram[currentIndex].data[1];
    ec_devinfo.build = readLittleEndianShort(ec_datagram[currentIndex].data + 2);
    ec_devinfo.fmmu_cnt = ec_datagram[currentIndex].data[4];
    ec_devinfo.sm_cnt = ec_datagram[currentIndex].data[5];
    ec_devinfo.dpram = ec_datagram[currentIndex].data[6];
    ec_devinfo.ports = ec_datagram[currentIndex].data[7];
    ec_devinfo.features = readLittleEndianShort(ec_datagram[currentIndex].data + 8);
    
    if(ecat_device)
    {
        event_mgr.Enqueue(ecat_device,
                          val_mgr->Count(ec_datagram[currentIndex].slave_addr),
                          val_mgr->Count(ec_devinfo.revision),
                          val_mgr->Count(ec_devinfo.type),
                          val_mgr->Count(ec_devinfo.build),
                          val_mgr->Count(ec_devinfo.fmmu_cnt),
                          val_mgr->Count(ec_devinfo.sm_cnt),
                          val_mgr->Count(ec_devinfo.ports),
                          val_mgr->Count(ec_devinfo.dpram),
                          val_mgr->Count(ec_devinfo.features));
    }
    
    return true;
}

bool ECATAnalyzer::processPDRAMData(uint8_t currentIndex)
{
    if(ec_datagram[currentIndex].length < MAILBOX_HEADER_SIZE)
    {
        return false;
    }
    ec_mailbox.header.length = readLittleEndianShort(ec_datagram[currentIndex].data);
    ec_mailbox.header.address = readLittleEndianShort(ec_datagram[currentIndex].data + 2);
    uint16_t otherBits = readBigEndianShort(ec_datagram[currentIndex].data + 4);
    uint8_t reserved = (otherBits & 0xFC) >> 10;
    ec_mailbox.header.priority = (otherBits & 0x0300) >> 8;
    ec_mailbox.header.counter = (otherBits & 0xF0) >> 4;
    ec_mailbox.header.type = otherBits & 0x0F;
    
    if(ec_datagram[currentIndex].length < MAILBOX_HEADER_SIZE + ec_mailbox.header.length)
    {
        return false;
    }
    
    // Try to parse the rest of the mailbox
    return parseMailbox(currentIndex);
}

bool ECATAnalyzer::parseMailbox(uint8_t currentIndex)
{
    switch(ec_mailbox.header.type)
    {
        case ecat_mbx_aoe:
            return parseAOE(currentIndex);
        case ecat_mbx_eoe:
            return parseEOE(currentIndex);
        case ecat_mbx_coe:
            return parseCOE(currentIndex);
        case ecat_mbx_foe:
            return parseFOE(currentIndex);
        case ecat_mbx_soe:
            return parseSOE(currentIndex);
        default:
            // Unknown, no parsing
            break;
    }
    return true;
}

bool ECATAnalyzer::parseAOE(uint8_t currentIndex)
{
    if(ec_mailbox.header.length < AOE_HEADER_SIZE)
    {
        return false;
    }
    
    const uint8_t* mailboxStart = ec_datagram[currentIndex].data + MAILBOX_HEADER_SIZE;
    
    for(int16_t i = AOE_ID_LENGTH-1; i >= 0; i--)
    {
        ec_mailbox.aoe.targetid[i] = mailboxStart[AOE_ID_LENGTH - i - 1];
    }
    uint16_t currentOffset = AOE_ID_LENGTH;
    
    ec_mailbox.aoe.targetport = readLittleEndianShort(mailboxStart + currentOffset);
    currentOffset += AOE_PORT_LENGTH;
    
    for(int16_t i = AOE_ID_LENGTH-1; i >= 0; i--)
    {
        ec_mailbox.aoe.senderid[i] = mailboxStart[currentOffset + (AOE_ID_LENGTH - i - 1)];
    }
    currentOffset += AOE_ID_LENGTH;
    
    ec_mailbox.aoe.senderport = readLittleEndianShort(mailboxStart + currentOffset);
    currentOffset += AOE_PORT_LENGTH;
    
    ec_mailbox.aoe.cmd = readLittleEndianShort(mailboxStart + currentOffset);
    currentOffset += 2;
    
    ec_mailbox.aoe.stateflags = readLittleEndianShort(mailboxStart + currentOffset);
    currentOffset += 2;
    
    ec_mailbox.aoe.cbdata = readLittleEndianInt(mailboxStart + currentOffset);
    currentOffset += 4;
    
    ec_mailbox.aoe.errorcode = readLittleEndianInt(mailboxStart + currentOffset);
    currentOffset += 4;
    
    ec_mailbox.aoe.invokeid = readLittleEndianInt(mailboxStart + currentOffset);
    currentOffset += 4;

    uint16_t dataSize = ec_mailbox.header.length - AOE_HEADER_SIZE;
    if(dataSize > 0)
    {
        memcpy(ec_mailbox.aoe.req_res, mailboxStart + AOE_HEADER_SIZE, dataSize);
    }
    
    if(ecat_AoE)
    {
        event_mgr.Enqueue(ecat_AoE,
                          ToEthAddrStr(ec_mailbox.aoe.targetid),
                          ToEthAddrStr(ec_mailbox.aoe.senderid),
                          val_mgr->Count(ec_mailbox.aoe.targetport),
                          val_mgr->Count(ec_mailbox.aoe.senderport),
                          val_mgr->Count(ec_mailbox.aoe.cmd),
                          val_mgr->Count(ec_mailbox.aoe.stateflags),
                          HexToString(ec_mailbox.aoe.req_res, dataSize));
    }
    
    return true;
}

bool ECATAnalyzer::parseEOE(uint8_t currentIndex)
{
    if(ec_mailbox.header.length < EOE_HEADER_SIZE)
    {
        return false;
    }
    
    const uint8_t* mailboxStart = ec_datagram[currentIndex].data + MAILBOX_HEADER_SIZE;
    
    Packet tempPacket;

    // Really confused by these values...
    // EoE Header is the first 4 bytes
    tempPacket.eth_type = readBigEndianShort(mailboxStart + 16);
    tempPacket.l2_dst = mailboxStart + 4;
    tempPacket.l2_src = mailboxStart + 10;
    tempPacket.len = ec_mailbox.header.length - 4;
    tempPacket.data = mailboxStart + 4;
    
    if(tempPacket.eth_type < 0x0800)
    {
        return false;
    }
    ForwardPacket(tempPacket.len, mailboxStart + 18, &tempPacket, tempPacket.eth_type);
    return true;
}

bool ECATAnalyzer::parseCOE(uint8_t currentIndex)
{
    if(ec_mailbox.header.length < COE_HEADER_SIZE)
    {
        return false;
    }
    
    const uint8_t* mailboxStart = ec_datagram[currentIndex].data + MAILBOX_HEADER_SIZE;

    ec_mailbox.coe.number = mailboxStart[0];
    ec_mailbox.coe.type = (mailboxStart[1] & 0xF0) >> 4;
    ec_mailbox.coe.req_resp = mailboxStart[2];
    ec_mailbox.coe.index = readLittleEndianShort(mailboxStart + 3);
    ec_mailbox.coe.subindex = mailboxStart[5];
    ec_mailbox.coe.data_offset = readLittleEndianInt(mailboxStart + 6);
    
    if(ecat_CoE)
    {
        event_mgr.Enqueue(ecat_CoE,
                          val_mgr->Count(ec_mailbox.coe.number),
                          val_mgr->Count(ec_mailbox.coe.type),
                          val_mgr->Count(ec_mailbox.coe.req_resp),
                          val_mgr->Count(ec_mailbox.coe.index),
                          val_mgr->Count(ec_mailbox.coe.subindex),
                          val_mgr->Count(ec_mailbox.coe.data_offset));
    }
    return true;
}

bool ECATAnalyzer::parseFOE(uint8_t currentIndex)
{
    if(ec_mailbox.header.length < FOE_HEADER_SIZE)
    {
        return false;
    }
    
    const uint8_t* mailboxStart = ec_datagram[currentIndex].data + MAILBOX_HEADER_SIZE;
    
    ec_mailbox.foe.opCode = mailboxStart[0];
    ec_mailbox.foe.reserved = mailboxStart[1];
    ec_mailbox.foe.password = readLittleEndianInt(mailboxStart + 2);
    ec_mailbox.foe.packet_num = readLittleEndianInt(mailboxStart + 6);
    ec_mailbox.foe.error_code = readLittleEndianInt(mailboxStart + 10);
    
    // See if optional fields exist
    if(ec_mailbox.header.length >= FOE_HEADER_SIZE + MAX_FOE_DATA_SIZE)
    {
        memcpy(ec_mailbox.foe.filename,
               mailboxStart + FOE_HEADER_SIZE,
               MAX_FOE_DATA_SIZE);
    }
    
    if(ec_mailbox.header.length >= FOE_HEADER_SIZE + 2 * MAX_FOE_DATA_SIZE)
    {
        memcpy(ec_mailbox.foe.data,
               mailboxStart + FOE_HEADER_SIZE + MAX_FOE_DATA_SIZE,
               MAX_FOE_DATA_SIZE);
    }
    
    if(ec_mailbox.header.length >= FOE_HEADER_SIZE + 3 * MAX_FOE_DATA_SIZE)
    {
        memcpy(ec_mailbox.foe.error_txt,
               mailboxStart + FOE_HEADER_SIZE + 2 * MAX_FOE_DATA_SIZE,
               MAX_FOE_DATA_SIZE);
    }
    
    if(ecat_FoE)
    {
        event_mgr.Enqueue(ecat_FoE,
                          val_mgr->Count(ec_mailbox.foe.opCode),
                          val_mgr->Count(ec_mailbox.foe.reserved),
                          val_mgr->Count(ec_mailbox.foe.packet_num),
                          val_mgr->Count(ec_mailbox.foe.error_code),
                          HexToString(ec_mailbox.foe.filename, MAX_FOE_DATA_SIZE),
                          HexToString(ec_mailbox.foe.data, MAX_FOE_DATA_SIZE));
    }
    
    return true;
}

bool ECATAnalyzer::parseSOE(uint8_t currentIndex)
{
    if(ec_mailbox.header.length < SOE_HEADER_SIZE)
    {
        return false;
    }
    
    const uint8_t* mailboxStart = ec_datagram[currentIndex].data + MAILBOX_HEADER_SIZE;
    
    ec_mailbox.soe.opCode = mailboxStart[0];
    ec_mailbox.soe.incomplete = mailboxStart[1];
    ec_mailbox.soe.error = mailboxStart[2];
    ec_mailbox.soe.drive_num = mailboxStart[3];
    ec_mailbox.soe.element_flags = mailboxStart[4];
    ec_mailbox.soe.index = readLittleEndianShort(mailboxStart + 5);
    
    if(ecat_SoE)
    {
        event_mgr.Enqueue(ecat_SoE,
                          val_mgr->Count(ec_mailbox.soe.opCode),
                          val_mgr->Count(ec_mailbox.soe.incomplete),
                          val_mgr->Count(ec_mailbox.soe.error),
                          val_mgr->Count(ec_mailbox.soe.drive_num),
                          val_mgr->Count(ec_mailbox.soe.element_flags),
                          val_mgr->Count(ec_mailbox.soe.index));
    }
    
    return true;
}

// -------------------------------ECATAnalyzer parseDatagramTrailer----------------------------------
// Message Description:
//      Parses the two byte EtherCAT Datagram Trailer
// Arguments:
//      - data:                  Data to be analyzed
//      - length:                Length of data
//      - currentIndex:          Datagram array index to use for storing data
// Return:
//      Returns whether or not there were enough bytes to parse the message trailer
// Protocol Parsing:
//      Parses data according to pack (note, packed as Little Endian)
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::parseDatagramTrailer(const uint8_t* data, size_t length, uint8_t currentIndex)
{
    if(length < DATAGRAM_TRAILER_LENGTH)
    {
        return false;
    }
    ec_datagram[currentIndex].working_counter = readLittleEndianShort(data);
    return true;
}

// -------------------------------ECATAnalyzer commandUsesRegularAddress----------------------------------
// Message Description:
//      Checks if the command uses a regular address or a Slave Address + Offset scheme
// Arguments:
//      - command:               Datagram Command
// Return:
//      Returns true if the command uses a regular address, otherwise false
// ------------------------------------------------------------------------------------------------
bool ECATAnalyzer::commandUsesRegularAddress(uint8_t command)
{
    switch(command)
    {
        case ecat_datagram_lrd:
            // Intentional Fallthrough
        case ecat_datagram_lwr:
            // Intentional Fallthrough
        case ecat_datagram_lrw:
            return true;
        default:
            return false;
    }
}

// -------------------------------ECATAnalyzer determineOffsetName----------------------------------
// Message Description:
//      Checks if the command uses a regular address or a Slave Address + Offset scheme
// Arguments:
//      - offsetAddress:         Datagram Offset Address
// Return:
//      The normalized Datagram Offset Address Name
// ------------------------------------------------------------------------------------------------
uint16_t ECATAnalyzer::determineOffsetName(uint16_t offsetAddress)
{
    // Just handle the ones with breaks:
    if(inDesiredRegisterRange(offsetAddress, build, fmmuspt))
    {
        return build;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_features, cs_addr))
    {
        return esc_features;
    }
    else if(inDesiredRegisterRange(offsetAddress, cs_addr, cs_alias))
    {
        return cs_addr;
    }
    else if(inDesiredRegisterRange(offsetAddress, cs_alias, reg_write_en))
    {
        return cs_alias;
    }
    else if(inDesiredRegisterRange(offsetAddress, reg_write_prot, esc_write_en))
    {
        return reg_write_prot;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_write_prot, esc_rst_ecat))
    {
        return esc_write_prot;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_rst_pdi, esc_dl_ctl))
    {
        return esc_rst_pdi;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_dl_ctl, phy_rd_wr_offs))
    {
        return esc_dl_ctl;
    }
    else if(inDesiredRegisterRange(offsetAddress, phy_rd_wr_offs, esc_dl_stat))
    {
        return phy_rd_wr_offs;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_dl_stat, al_ctrl))
    {
        return esc_dl_stat;
    }
    else if(inDesiredRegisterRange(offsetAddress, al_ctrl, al_stat))
    {
        return al_ctrl;
    }
    else if(inDesiredRegisterRange(offsetAddress, al_stat, al_stat_code))
    {
        return al_stat;
    }
    else if(inDesiredRegisterRange(offsetAddress, al_stat_code, run_led_ovrd))
    {
        return al_stat_code;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_conf, pdi_info))
    {
        return esc_conf;
    }
    else if(inDesiredRegisterRange(offsetAddress, pdi_info, pdi_conf))
    {
        return pdi_info;
    }
    else if(inDesiredRegisterRange(offsetAddress, pdi_onchip_conf, ecat_ev_msk))
    {
        return pdi_onchip_conf;
    }
    else if(inDesiredRegisterRange(offsetAddress, ecat_ev_msk, pdi_al_ev_msk))
    {
        return ecat_ev_msk;
    }
    else if(inDesiredRegisterRange(offsetAddress, pdi_al_ev_msk, ecat_ev_req))
    {
        return pdi_al_ev_msk;
    }
    else if(inDesiredRegisterRange(offsetAddress, ecat_ev_req, al_ev_req))
    {
        return ecat_ev_req;
    }
    else if(inDesiredRegisterRange(offsetAddress, al_ev_req, rx_err_cnt))
    {
        return al_ev_req;
    }
    else if(inDesiredRegisterRange(offsetAddress, rx_err_cnt, fwd_rx_err_cnt))
    {
        return rx_err_cnt;
    }
    else if(inDesiredRegisterRange(offsetAddress, fwd_rx_err_cnt, ecat_proc_err_cnt))
    {
        return fwd_rx_err_cnt;
    }
    else if(inDesiredRegisterRange(offsetAddress, pdi_err_code, llc))
    {
        return pdi_err_code;
    }
    else if(inDesiredRegisterRange(offsetAddress, llc, wtd_div))
    {
        return llc;
    }
    else if(inDesiredRegisterRange(offsetAddress, wtd_div, wtd_time_pdi))
    {
        return wtd_div;
    }
    else if(inDesiredRegisterRange(offsetAddress, wtd_time_pdi, wtd_time_proc_data))
    {
        return wtd_time_pdi;
    }
    else if(inDesiredRegisterRange(offsetAddress, wtd_time_proc_data, wtd_stat_proc_data))
    {
        return wtd_time_proc_data;
    }
    else if(inDesiredRegisterRange(offsetAddress, wtd_stat_proc_data, wtd_cnt_proc_data))
    {
        return wtd_stat_proc_data;
    }
    else if(inDesiredRegisterRange(offsetAddress, wtd_cnt_pdi, sii_eeprom_intr))
    {
        return wtd_cnt_pdi;
    }
    else if(inDesiredRegisterRange(offsetAddress, sii_eeprom_intr, mii_mang_intr))
    {
        return sii_eeprom_intr;
    }
    else if(inDesiredRegisterRange(offsetAddress, mii_mang_intr, fmmu))
    {
        return mii_mang_intr;
    }
    else if(inDesiredRegisterRange(offsetAddress, fmmu, sync_manager))
    {
        return fmmu;
    }
    else if(inDesiredRegisterRange(offsetAddress, sync_manager, dist_clk))
    {
        return sync_manager;
    }
    else if(inDesiredRegisterRange(offsetAddress, dist_clk, esc_specf_reg))
    {
        return dist_clk;
    }
    else if(inDesiredRegisterRange(offsetAddress, esc_specf_reg, dig_io_data))
    {
        return esc_specf_reg;
    }
    else if(inDesiredRegisterRange(offsetAddress, dig_io_data, gp_out_data))
    {
        return dig_io_data;
    }
    else if(inDesiredRegisterRange(offsetAddress, gp_out_data, gp_in))
    {
        return gp_out_data;
    }
    else if(inDesiredRegisterRange(offsetAddress, gp_in, usr_ram))
    {
        return gp_in;
    }
    else if(inDesiredRegisterRange(offsetAddress, usr_ram, pd_ram))
    {
        return usr_ram;
    }
    else if(offsetAddress >= pd_ram)
    {
        return pd_ram;
    }
    else
    {
        // No range, just return itself
        return offsetAddress;
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
