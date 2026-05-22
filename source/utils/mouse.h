#pragma once

#include <ntifs.h>
#include <ntddmou.h>

namespace mouse
{
    bool MoveRelative(LONG x, LONG y);
}
