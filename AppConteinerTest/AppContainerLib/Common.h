#pragma once

#include <string>
#include <memory>
#include <Windows.h>
#include <userenv.h>
#include <iostream>
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include <vector>

const std::vector<WELL_KNOWN_SID_TYPE> appCapabilities =
{
    WinCapabilityRemovableStorageSid,
};

