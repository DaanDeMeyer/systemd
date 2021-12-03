/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-messages.h"

#include "errno-util.h"
#include "json-util.h"

int json_log_internal(
                JsonVariant *variant,
                int level,
                int error,
                const char *file,
                int line,
                const char *func,
                const char *format, ...) {

        PROTECT_ERRNO;

        unsigned source_line, source_column;
        char buffer[LINE_MAX];
        const char *source;
        va_list ap;
        int r;

        errno = ERRNO_VALUE(error);

        va_start(ap, format);
        (void) vsnprintf(buffer, sizeof buffer, format, ap);
        va_end(ap);

        if (variant) {
                r = json_variant_get_source(variant, &source, &source_line, &source_column);
                if (r < 0)
                        return r;
        } else {
                source = NULL;
                source_line = 0;
                source_column = 0;
        }

        if (source && source_line > 0 && source_column > 0)
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                                "CONFIG_FILE=%s", source,
                                "CONFIG_LINE=%u", source_line,
                                "CONFIG_COLUMN=%u", source_column,
                                LOG_MESSAGE("%s:%u:%u: %s", source, source_line, source_column, buffer),
                                NULL);
        else if (source_line > 0 && source_column > 0)
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                                "CONFIG_LINE=%u", source_line,
                                "CONFIG_COLUMN=%u", source_column,
                                LOG_MESSAGE("(string):%u:%u: %s", source_line, source_column, buffer),
                                NULL);
        else
                return log_struct_internal(
                                level,
                                error,
                                file, line, func,
                                "MESSAGE_ID=" SD_MESSAGE_INVALID_CONFIGURATION_STR,
                                LOG_MESSAGE("%s", buffer),
                                NULL);
}
