#pragma once

#include <windows.h>
#include "pe_loader.h"

typedef __declspec(dllimport) BOOL (CALLBACK *beep_func_t)( DWORD msg );