# ICSNPP-ETHERCAT

Industrial Control Systems Network Protocol Parsers (ICSNPP) - Ethercat.

## Overview

ICSNPP-Ethercat is a Zeek plugin for parsing and logging fields within the Ethercat protocol.

This plugin was developed to be fully customizable, so if you would like to drill down into specific Ethercat packets and log certain variables, add the logging functionality to [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek). The functions within [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek) and [src/events.bif](src/events.bif) should prove to be a good guide on how to add new logging functionality.

This parser produces 8 log files. These log files are defined in [scripts/icsnpp/ethercat/main.zeek](scripts/icsnpp/ethercat/main.zeek).
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

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::ETHERCAT`.

If you have ZKG configured to load packages (see @load packages in quickstart guide), this plugin and scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/ethercat` to your command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-bacnet.git
zeek -Cr ethercat-bacnet/examples/ethercat_example.pcap icsnpp/ethercat
```


## Manual Install
To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-ethercat.git
cd icsnpp-ethercat/
./configure
make
```
If these commands succeed, you will end up with a newly created build directory which contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::ETHERCAT
```
Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:

```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::ETHERCAT
```
To run this plugin in a site deployment you will need to add the line @load icsnpp/ethercat to your site/local.zeek file in order to load this plugin's scripts.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add icsnpp/ethercat to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-ethercat/examples/ethercat_example.pcap icsnpp/ethercat
```
If you want to deploy this plugin on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the ICSNPP_ETHERCAT.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is ${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/).

```bash
tar xvzf build/ICSNPP_Ethercat.tgz -C $ZEEK_PLUGIN_PATH 
```
## Logging Capabilities

### ECAT Registers (ecat_registers.log)

#### Overview

This log captures register memory address read and writes **ecat_registers.log**.

This log is also the catch all. Before it gets to this point it is sent through the more parsing routines to pull out any other information. ie. CoE, AoE, FoE, EoE, and SoE mailbox data. 

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| srcmac            | string    | Source Mac Address                                        |
| dstmac            | string    | Destination Mac Address                                   |
| Command           | string    | Ethercat Command                                          |
| Slave_Addr        | string    | Ethercat Slave Address                                    |
| Register_Type     | string    | Register Information                                      |
| Register_Addr     | string    | Memory Address being accessed                             |
| data              | string    | Data to be read or wrote to memory address                |


### ECAT Address read write (ecat_log_address.log)

#### Overview

This log captures Logical Read and writes to addresses and logs them to **ecat_log_address.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| srcmac            | string    | Source Mac Address                                        |
| dstmac            | string    | Destination Mac Address                                   |
| Log_Addr          | string    | Address data is being accessed from                       |
| Length            | count     | Length of data                                            |
| Command           | string    | Ethercat Command                                          |
| data              | string    | Data read or write                                        |

### ECAT Device Info (ecat_dev_info.log)

#### Overview

This log captures ECAT Device info and logs it to **ecat_dev_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| slave_id          | string    | Ethercat Slave Address                                    |
| revision          | string    | Revision of EtherCAT controller 					        |
| dev_type          | string    | Type of EtherCAT controller                               |
| build             | string    | Build version                                             |
| fmmucnt           | string    | Fieldbus Memory Management Unit supported channel count   |
| smcount           | string    | Sync Manager count                                        |
| ports             | string    | Port Descriptor                                           |
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
| targetid          | string    | Target Network ID                                         |
| targetport        | string    | Target Port                                               |
| senderid          | string    | Sender Network ID                                         |
| senderport        | string    | Sender Port                                               |
| cmd               | string    | Command                                                   |
| stateflags        | string    | State Flags                                               |
| data              | string    | Command Data                                              |

### ECAT CoE Info (ecat_coe_info.log)

#### Overview

This log captures CoE (CAN over Ethercat) and logs it to **ecat_coe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| number            | string    | Message number                                            |
| Type              | string    | Message Type                                              |
| req_resp          | string    | Request or Response type                                  |
| index             | string    | Index                                                     |
| subindex          | string    | Sub Index                                                 |
| dataoffset        | string    | Data Offset                                               |

### ECAT FoE Info (ecat_foe_info.log)

#### Overview

This log captures FoE (File Over Ethercat) information and logs it to **ecat_foe_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| opCode            | string    | Operation Code                                            |
| reserved          | string    | Reserved                                                  |
| packet_num        | string    | Packet number                                             |
| error_code        | string    | Error Code                                                |
| filename          | string    | Filename                                                  |
| data              | string    | Transferred Data                                          |

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
| element_flags     | string    | Element Flags                                             |
| index             | string    | Message Index                                             |

### ECAT ARP Info (ecat_arp_info.log)

#### Overview

This log captures ARP info that is passed through EoE (Ethernet over Ethercat)
and logs it to **ecat_arp_info.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| arp_type          | string    | Arp command                                               |
| mac_src           | string    | Source Mac address                                        |
| mac_dst           | string    | Destination Mac address                                   |
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

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilites of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilites of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2020 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.