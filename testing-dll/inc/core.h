#pragma once

#include <windows.h>

#define EXPORT __declspec(dllexport)

EXPORT BOOL CALLBACK test_beep( DWORD );