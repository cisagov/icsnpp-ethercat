# ICSNPP-ETHERCAT

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Ethercat.

## Overview

ICSNPP-Ethercat is a Zeek plugin for parsing and logging fields within the Ethercat protocol.

This plugin was developed to be fully customizable. To drill down into specific Ethercat packets and log certain variables, users can add the logging functionality to [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek). The functions within [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek) and [src/events.bif](src/events.bif) are good guides for adding new logging functionality.

This parser produces eight log files. These log files are defined in [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek).
* ecat_registers.log
* ecat_log_address.log
* ecat_dev_info.log 
* ecat_aoe_info.log 
* ecat_coe_info.log 
* ecat_foe_info.log 
* ecat_soe_info.log 
* ecat_arp_info.log 

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Installing Zeek

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-ethercat
```

If this package is installed from ZKG, it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly, users will see `ICSNPP::ETHERCAT`.

If ZKG is configured to load packages (see @load packages in quickstart guide), this plugin and these scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add `icsnpp/ethercat` to the command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-ethercat.git
zeek -Cr icsnpp-ethercat/tests/traces/ethercat_example.pcap icsnpp/ethercat
```


## Manual Install
To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-ethercat.git
cd icsnpp-ethercat/
./configure
make
```
If these commands succeed, users will end up with a newly created build directory that contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::ETHERCAT
```
Once users have tested the functionality locally and it appears to have compiled correctly, they can install it system-wide:

```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::ETHERCAT
```
To run this plugin in a site deployment, users will need to add the line @load icsnpp/ethercat to the site/local.zeek file to load this plugin's scripts.

If users are not using site/local.zeek or another site installation of Zeek and want to run this package on a packet capture, they can add icsnpp/ethercat to the command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-ethercat/tests/traces/ethercat_example.pcap icsnpp/ethercat
```
If users want to deploy this plugin on an already existing Zeek implementation and don't want to build the plugin on the machine, they can extract the ICSNPP_ETHERCAT.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is ${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/).

```bash
tar xvzf build/ICSNPP_Ethercat.tgz -C $ZEEK_PLUGIN_PATH 
```
## Logging Capabilities

### ECAT Registers (ecat_registers.log)

#### Overview

This log captures register memory address read and writes **ecat_registers.log**.

This log is also the catch all. Before it gets to this point it is sent through more parsing routines to pull out any other information (i.e., CoE, AoE, FoE, EoE, and SoE mailbox data). 

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| srcmac            | string    | Source MAC address                                        |
| dstmac            | string    | Destination MAC address                                   |
| Command           | string    | EtherCAT command                                          |
| Slave_Addr        | string    | EtherCAT slave address                                    |
| Register_Type     | string    | Register information                                      |
| Register_Addr     | string    | Memory address being accessed                             |
| data              | string    | Data to be read or wrote to memory address                |


### ECAT Address read write (ecat_log_address.log)

#### Overview

This log captures Logical Read and writes to addresses and logs them to **ecat_log_address.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| srcmac            | string    | Source MAC address                                        |
| dstmac            | string    | Destination MAC address                                   |
| Log_Addr          | string    | Address data is being accessed from                       |
| Length            | count     | Length of data                                            |
| Command           | string    | EtherCAT command                                          |
| data              | string    | Data read or write                                        |

### ECAT Device Info (ecat_dev_info.log)

#### Overview

This log captures ECAT Device info and logs it to **ecat_dev_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| slave_id          | string    | Ethercat slave address                                    |
| revision          | string    | Revision of EtherCAT controller 					        |
| dev_type          | string    | Type of EtherCAT controller                               |
| build             | string    | Build version                                             |
| fmmucnt           | string    | Fieldbus memory management unit supported channel count   |
| smcount           | string    | Sync manager count                                        |
| ports             | string    | Port descriptor                                           |
| dpram             | string    | Ram size                                                  |
| features          | string    | Features supported                                        |

### ECAT AoE Info (ecat_aoe_info.log)

#### Overview

This log captures AoE (ADS over Ethercat, Automation Device Specification) information 
and logs it to **ecat_aoe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| targetid          | string    | Target network ID                                         |
| targetport        | string    | Target port                                               |
| senderid          | string    | Sender network ID                                         |
| senderport        | string    | Sender port                                               |
| cmd               | string    | Command                                                   |
| stateflags        | string    | State flags                                               |
| data              | string    | Command data                                              |

### ECAT CoE Info (ecat_coe_info.log)

#### Overview

This log captures CoE (CAN over Ethercat) and logs it to **ecat_coe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| number            | string    | Message number                                            |
| Type              | string    | Message type                                              |
| req_resp          | string    | Request or response type                                  |
| index             | string    | Index                                                     |
| subindex          | string    | Sub index                                                 |
| dataoffset        | string    | Data offset                                               |

### ECAT FoE Info (ecat_foe_info.log)

#### Overview

This log captures FoE (File Over Ethercat) information and logs it to **ecat_foe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| opCode            | string    | Operation code                                            |
| reserved          | string    | Reserved                                                  |
| packet_num        | string    | Packet number                                             |
| error_code        | string    | Error code                                                |
| filename          | string    | Filename                                                  |
| data              | string    | Transferred data                                          |

### ECAT SoE Info (ecat_soe_info.log)

#### Overview

This log captures SoE (Servo over Ethercat) and logs it to **ecat_soe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| opCode            | string    | Command sent for controller                               |
| incomplete        | string    | Function check to determine if it has been processed      |
| error             | string    | Error message                                             |
| drive_num         | string    | Drive number for command                                  |
| element_flags     | string    | Element flags                                             |
| index             | string    | Message index                                             |

### ECAT ARP Info (ecat_arp_info.log)

#### Overview

This log captures ARP info that is passed through EoE (Ethernet over Ethercat)
and logs it to **ecat_arp_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| arp_type          | string    | ARP command                                               |
| mac_src           | string    | Source MAC address                                        |
| mac_dst           | string    | Destination MAC address                                   |
| SPA               | addr      | Sender protocol address                                   |
| SHA               | string    | Sender hardware address                                   |
| TPA               | addr      | Target protocol address                                   |
| THA               | string    | Target hardware address                                   |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [GE SRTP](https://github.com/cisagov/icsnpp-ge-srtp)
    * Full Zeek protocol parser for GE SRTP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)
* [Profinet IO CM](https://github.com/cisagov/icsnpp-profinet-io-cm)
    * Full Zeek protocol parser for Profinet I/O Context Manager

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### License

Copyright 2023 Battelle Energy Alliance, LLC. Released under the terms of the 3-Clause BSD License (see [`LICENSE.txt`](./LICENSE.txt)).
