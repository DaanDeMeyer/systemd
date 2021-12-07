/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

static inline int sd_json_dispatch_level(sd_json_dispatch_flags_t flags) {

        /* Did the user request no logging? If so, then never log higher than LOG_DEBUG. Also, if this is marked as
         * debug message, then also log at debug level. */

        if (!(flags & SD_JSON_LOG) ||
            (flags & SD_JSON_DEBUG))
                return LOG_DEBUG;

        /* Are we invoked in permissive mode, or is this explicitly marked as warning message? Then this should be
         * printed at LOG_WARNING */
        if (flags & (SD_JSON_PERMISSIVE|SD_JSON_WARNING))
                return LOG_WARNING;

        /* Otherwise it's an error. */
        return LOG_ERR;
}

int json_log_internal(sd_json_variant *variant, int level, int error, const char *file, int line, const char *func, const char *format, ...)  _printf_(7, 8);

#define json_log(variant, flags, error, ...)                            \
        ({                                                              \
                int _level = sd_json_dispatch_level(flags), _e = (error);  \
                (log_get_max_level() >= LOG_PRI(_level))                \
                        ? json_log_internal(variant, _level, _e, PROJECT_FILE, __LINE__, __func__, __VA_ARGS__) \
                        : -ERRNO_VALUE(_e);                             \
        })

#define json_log_oom(variant, flags) \
        json_log(variant, flags, SYNTHETIC_ERRNO(ENOMEM), "Out of memory.")
