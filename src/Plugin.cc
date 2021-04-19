// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved."

#include "Plugin.h"
#include "packet_analysis/Component.h"

namespace plugin 
{
    namespace ICSNPP_ETHERCAT
    {
        Plugin plugin;
    }
}

using namespace plugin::ICSNPP_ETHERCAT;

zeek::plugin::Configuration Plugin::Configure()
{
    AddComponent(new zeek::packet_analysis::Component("ETHERCAT",
                     zeek::packet_analysis::ETHERCAT::ECATAnalyzer::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "ICSNPP::ETHERCAT";
    config.description = "Ethercat packet analyzer";
    config.version.major = 1;
    config.version.minor = 0;
    
    return config;
}

