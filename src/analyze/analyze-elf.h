/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

int analyze_elf(char **filenames, sd_json_format_flags_t json_flags);
