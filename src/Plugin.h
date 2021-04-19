// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
#pragma once

#include <plugin/Plugin.h>
#include "ECAT.h"

namespace plugin 
{
    namespace ICSNPP_ETHERCAT
    {
        class Plugin : public ::plugin::Plugin
        {
            protected:
                virtual zeek::plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}