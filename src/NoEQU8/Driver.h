#pragma once
#include "util.h"

typedef NTSTATUS(__fastcall* EQ_AddTrustedProcessById_t)(PVOID trustedProcessList, unsigned int processId);
