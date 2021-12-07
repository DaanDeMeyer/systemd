/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "sd-id128.h"

#include "_sd-common.h"

/*
  In case you wonder why we have our own JSON implementation, here are a couple of reasons why this implementation has
  benefits over various other implementations:

  - We need support for 64bit signed and unsigned integers, i.e. the full 64,5bit range of -9223372036854775808…18446744073709551615
  - All our variants are immutable after creation
  - Special values such as true, false, zero, null, empty strings, empty array, empty objects require zero dynamic memory
  - Progressive parsing
  - Our integer/real type implicitly converts, but only if that's safe and loss-lessly possible
  - There's a "builder" for putting together objects easily in varargs function calls
  - There's a "dispatcher" for mapping objects to C data structures
  - Every variant optionally carries parsing location information, which simplifies debugging and parse log error generation
  - Formatter has color, line, column support

  Limitations:
  - Doesn't allow embedded NUL in strings
  - Can't store integers outside of the -9223372036854775808…18446744073709551615 range (it will use 'double' for
    values outside this range, which is lossy)
  - Can't store negative zero (will be treated identical to positive zero, and not retained across serialization)
  - Can't store non-integer numbers that can't be stored in "double" losslessly
  - Allows creation and parsing of objects with duplicate keys. The "dispatcher" will refuse them however. This means
    we can parse and pass around such objects, but will carefully refuse them when we convert them into our own data.

  (These limitations should be pretty much in line with those of other JSON implementations, in fact might be less
  limiting in most cases even.)
*/

typedef struct sd_json_variant sd_json_variant;

typedef enum sd_json_variant_type_t {
        SD_JSON_VARIANT_STRING,
        SD_JSON_VARIANT_INTEGER,
        SD_JSON_VARIANT_UNSIGNED,
        SD_JSON_VARIANT_REAL,
        SD_JSON_VARIANT_NUMBER, /* This a pseudo-type: we can never create variants of this type, but we use it as wildcard check for the above three types */
        SD_JSON_VARIANT_BOOLEAN,
        SD_JSON_VARIANT_ARRAY,
        SD_JSON_VARIANT_OBJECT,
        SD_JSON_VARIANT_NULL,
        _SD_JSON_VARIANT_TYPE_MAX,
        _SD_JSON_VARIANT_TYPE_INVALID = -EINVAL,

        _SD_ENUM_FORCE_S64(JSON_VARIANT),
} sd_json_variant_type_t;

int sd_json_variant_new_stringn(sd_json_variant **ret, const char *s, size_t n);
int sd_json_variant_new_string(sd_json_variant **ret, const char *s);
int sd_json_variant_new_base64(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_hex(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_integer(sd_json_variant **ret, int64_t i);
int sd_json_variant_new_unsigned(sd_json_variant **ret, uint64_t u);
int sd_json_variant_new_real(sd_json_variant **ret, double d);
int sd_json_variant_new_boolean(sd_json_variant **ret, bool b);
int sd_json_variant_new_array(sd_json_variant **ret, sd_json_variant **array, size_t n);
int sd_json_variant_new_array_bytes(sd_json_variant **ret, const void *p, size_t n);
int sd_json_variant_new_array_strv(sd_json_variant **ret, char **l);
int sd_json_variant_new_object(sd_json_variant **ret, sd_json_variant **array, size_t n);
int sd_json_variant_new_null(sd_json_variant **ret);
int sd_json_variant_new_id128(sd_json_variant **ret, sd_id128_t id);

sd_json_variant *sd_json_variant_ref(sd_json_variant *v);
sd_json_variant *sd_json_variant_unref(sd_json_variant *v);
void sd_json_variant_unref_many(sd_json_variant **array, size_t n);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_json_variant, sd_json_variant_unref);

const char *sd_json_variant_string(sd_json_variant *v);
int64_t sd_json_variant_integer(sd_json_variant *v);
uint64_t sd_json_variant_unsigned(sd_json_variant *v);
double sd_json_variant_real(sd_json_variant *v);
bool sd_json_variant_boolean(sd_json_variant *v);

sd_json_variant_type_t sd_json_variant_type(sd_json_variant *v);
bool sd_json_variant_has_type(sd_json_variant *v, sd_json_variant_type_t type);

bool sd_json_variant_is_string(sd_json_variant *v);
bool sd_json_variant_is_integer(sd_json_variant *v);
bool sd_json_variant_is_unsigned(sd_json_variant *v);
bool sd_json_variant_is_real(sd_json_variant *v);
bool sd_json_variant_is_number(sd_json_variant *v);
bool sd_json_variant_is_boolean(sd_json_variant *v);
bool sd_json_variant_is_array(sd_json_variant *v);
bool sd_json_variant_is_object(sd_json_variant *v);
bool sd_json_variant_is_null(sd_json_variant *v);

bool sd_json_variant_is_negative(sd_json_variant *v);
bool sd_json_variant_is_blank_object(sd_json_variant *v);
bool sd_json_variant_is_blank_array(sd_json_variant *v);
bool sd_json_variant_is_normalized(sd_json_variant *v);
bool sd_json_variant_is_sorted(sd_json_variant *v);

size_t sd_json_variant_elements(sd_json_variant *v);
sd_json_variant *sd_json_variant_by_index(sd_json_variant *v, size_t index);
sd_json_variant *sd_json_variant_by_key(sd_json_variant *v, const char *key);
sd_json_variant *sd_json_variant_by_key_full(sd_json_variant *v, const char *key, sd_json_variant **ret_key);

bool sd_json_variant_equal(sd_json_variant *a, sd_json_variant *b);

void sd_json_variant_sensitive(sd_json_variant *v);
bool sd_json_variant_is_sensitive(sd_json_variant *v);

struct sd_json_variant_foreach_state {
        sd_json_variant *variant;
        size_t idx;
};

#define _SD_JSON_VARIANT_ARRAY_FOREACH(i, v, state)                        \
        for (struct sd_json_variant_foreach_state state = { (v), 0 };      \
             sd_json_variant_is_array(state.variant) &&                    \
                     state.idx < sd_json_variant_elements(state.variant) && \
                     ({ i = sd_json_variant_by_index(state.variant, state.idx); \
                             true; });                                  \
             state.idx++)
#define SD_JSON_VARIANT_ARRAY_FOREACH(i, v)                                \
        _SD_JSON_VARIANT_ARRAY_FOREACH(i, v, UNIQ_T(state, UNIQ))

#define _SD_JSON_VARIANT_OBJECT_FOREACH(k, e, v, state)                    \
        for (struct sd_json_variant_foreach_state state = { (v), 0 };      \
             sd_json_variant_is_object(state.variant) &&                   \
                     state.idx < sd_json_variant_elements(state.variant) && \
                     ({ k = sd_json_variant_string(sd_json_variant_by_index(state.variant, state.idx)); \
                             e = sd_json_variant_by_index(state.variant, state.idx + 1); \
                             true; });                                  \
             state.idx += 2)
#define SD_JSON_VARIANT_OBJECT_FOREACH(k, e, v)                            \
        _SD_JSON_VARIANT_OBJECT_FOREACH(k, e, v, UNIQ_T(state, UNIQ))

int sd_json_variant_get_source(sd_json_variant *v, const char **ret_source, unsigned *ret_line, unsigned *ret_column);

typedef enum sd_json_format_flags_t {
        SD_JSON_FORMAT_NEWLINE     = 1 << 0, /* suffix with newline */
        SD_JSON_FORMAT_PRETTY      = 1 << 1, /* add internal whitespace to appeal to human readers */
        SD_JSON_FORMAT_PRETTY_AUTO = 1 << 2, /* same, but only if connected to a tty (and SD_JSON_FORMAT_NEWLINE otherwise) */
        SD_JSON_FORMAT_COLOR       = 1 << 3, /* insert ANSI color sequences */
        SD_JSON_FORMAT_COLOR_AUTO  = 1 << 4, /* insert ANSI color sequences if colors_enabled() says so */
        SD_JSON_FORMAT_SOURCE      = 1 << 5, /* prefix with source filename/line/column */
        SD_JSON_FORMAT_SSE         = 1 << 6, /* prefix/suffix with W3C server-sent events */
        SD_JSON_FORMAT_SEQ         = 1 << 7, /* prefix/suffix with RFC 7464 application/json-seq */
        SD_JSON_FORMAT_FLUSH       = 1 << 8, /* call fflush() after dumping JSON */
        SD_JSON_FORMAT_OFF         = 1 << 9, /* make sd_json_variant_format() fail with -ENOEXEC */

        _SD_ENUM_FORCE_U64(JSON_FORMAT),
} sd_json_format_flags_t;

int sd_json_variant_format(sd_json_variant *v, sd_json_format_flags_t flags, char **ret);
void sd_json_variant_dump(sd_json_variant *v, sd_json_format_flags_t flags, FILE *f, const char *prefix);

int sd_json_variant_filter(sd_json_variant **v, char **to_remove);

int sd_json_variant_set_field(sd_json_variant **v, const char *field, sd_json_variant *value);
int sd_json_variant_set_field_string(sd_json_variant **v, const char *field, const char *value);
int sd_json_variant_set_field_integer(sd_json_variant **v, const char *field, int64_t value);
int sd_json_variant_set_field_unsigned(sd_json_variant **v, const char *field, uint64_t value);
int sd_json_variant_set_field_boolean(sd_json_variant **v, const char *field, bool b);
int sd_json_variant_set_field_strv(sd_json_variant **v, const char *field, char **l);

int sd_json_variant_append_array(sd_json_variant **v, sd_json_variant *element);

int sd_json_variant_merge(sd_json_variant **v, sd_json_variant *m);

int sd_json_variant_strv(sd_json_variant *v, char ***ret);

int sd_json_variant_sort(sd_json_variant **v);
int sd_json_variant_normalize(sd_json_variant **v);

typedef enum sd_json_parse_flags_t {
        SD_JSON_PARSE_SENSITIVE = 1 << 0, /* mark variant as "sensitive", i.e. something containing secret key material or such */

        _SD_ENUM_FORCE_U64(JSON_PARSE)
} sd_json_parse_flags_t;

int sd_json_parse(const char *string, sd_json_parse_flags_t flags, sd_json_variant **ret, unsigned *ret_line, unsigned *ret_column);
int sd_json_parse_continue(const char **p, sd_json_parse_flags_t flags, sd_json_variant **ret, unsigned *ret_line, unsigned *ret_column);
int sd_json_parse_file_at(FILE *f, int dir_fd, const char *path, sd_json_parse_flags_t flags, sd_json_variant **ret, unsigned *ret_line, unsigned *ret_column);
int sd_json_parse_file(FILE *f, const char *path, sd_json_parse_flags_t flags, sd_json_variant **ret, unsigned *ret_line, unsigned *ret_column);

enum {
        _SD_JSON_BUILD_STRING,
        _SD_JSON_BUILD_INTEGER,
        _SD_JSON_BUILD_UNSIGNED,
        _SD_JSON_BUILD_REAL,
        _SD_JSON_BUILD_BOOLEAN,
        _SD_JSON_BUILD_ARRAY_BEGIN,
        _SD_JSON_BUILD_ARRAY_END,
        _SD_JSON_BUILD_OBJECT_BEGIN,
        _SD_JSON_BUILD_OBJECT_END,
        _SD_JSON_BUILD_PAIR,
        _SD_JSON_BUILD_PAIR_CONDITION,
        _SD_JSON_BUILD_NULL,
        _SD_JSON_BUILD_VARIANT,
        _SD_JSON_BUILD_VARIANT_ARRAY,
        _SD_JSON_BUILD_LITERAL,
        _SD_JSON_BUILD_STRV,
        _SD_JSON_BUILD_BASE64,
        _SD_JSON_BUILD_HEX,
        _SD_JSON_BUILD_ID128,
        _SD_JSON_BUILD_BYTE_ARRAY,
        _SD_JSON_BUILD_HW_ADDR,
        _SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO,
        _SD_JSON_BUILD_PAIR_FINITE_USEC,
        _SD_JSON_BUILD_PAIR_STRING_NON_EMPTY,
        _SD_JSON_BUILD_PAIR_STRV_NON_EMPTY,
        _SD_JSON_BUILD_PAIR_VARIANT_NON_NULL,
        _SD_JSON_BUILD_PAIR_VARIANT_ARRAY_NON_EMPTY,
        _SD_JSON_BUILD_PAIR_IN4_ADDR_NON_NULL,
        _SD_JSON_BUILD_PAIR_IN6_ADDR_NON_NULL,
        _SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL,
        _SD_JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL,
        _SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL,
        _SD_JSON_BUILD_MAX,
};

#define SD_JSON_BUILD_STRING(s) _SD_JSON_BUILD_STRING, (const char*) { s }
#define SD_JSON_BUILD_INTEGER(i) _SD_JSON_BUILD_INTEGER, (int64_t) { i }
#define SD_JSON_BUILD_UNSIGNED(u) _SD_JSON_BUILD_UNSIGNED, (uint64_t) { u }
#define SD_JSON_BUILD_REAL(d) _SD_JSON_BUILD_REAL, (double) { d }
#define SD_JSON_BUILD_BOOLEAN(b) _SD_JSON_BUILD_BOOLEAN, (bool) { b }
#define SD_JSON_BUILD_ARRAY(...) _SD_JSON_BUILD_ARRAY_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_EMPTY_ARRAY _SD_JSON_BUILD_ARRAY_BEGIN, _SD_JSON_BUILD_ARRAY_END
#define SD_JSON_BUILD_OBJECT(...) _SD_JSON_BUILD_OBJECT_BEGIN, __VA_ARGS__, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_EMPTY_OBJECT _SD_JSON_BUILD_OBJECT_BEGIN, _SD_JSON_BUILD_OBJECT_END
#define SD_JSON_BUILD_PAIR(n, ...) _SD_JSON_BUILD_PAIR, (const char*) { n }, __VA_ARGS__
#define SD_JSON_BUILD_PAIR_CONDITION(c, n, ...) _SD_JSON_BUILD_PAIR_CONDITION, (bool) { c }, (const char*) { n }, __VA_ARGS__
#define SD_JSON_BUILD_NULL _SD_JSON_BUILD_NULL
#define SD_JSON_BUILD_VARIANT(v) _SD_JSON_BUILD_VARIANT, (sd_json_variant*) { v }
#define SD_JSON_BUILD_VARIANT_ARRAY(v, n) _SD_JSON_BUILD_VARIANT_ARRAY, (sd_json_variant **) { v }, (size_t) { n }
#define SD_JSON_BUILD_LITERAL(l) _SD_JSON_BUILD_LITERAL, (const char*) { l }
#define SD_JSON_BUILD_STRV(l) _SD_JSON_BUILD_STRV, (char**) { l }
#define SD_JSON_BUILD_BASE64(p, n) _SD_JSON_BUILD_BASE64, (const void*) { p }, (size_t) { n }
#define SD_JSON_BUILD_HEX(p, n) _SD_JSON_BUILD_HEX, (const void*) { p }, (size_t) { n }
#define SD_JSON_BUILD_ID128(id) _SD_JSON_BUILD_ID128, (const sd_id128_t*) { &(id) }
#define SD_JSON_BUILD_BYTE_ARRAY(v, n) _SD_JSON_BUILD_BYTE_ARRAY, (const void*) { v }, (size_t) { n }
#define SD_JSON_BUILD_CONST_STRING(s) _SD_JSON_BUILD_VARIANT, SD_JSON_VARIANT_STRING_CONST(s)
#define SD_JSON_BUILD_IN4_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY((const struct in_addr*) { v }, sizeof(struct in_addr))
#define SD_JSON_BUILD_IN6_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY((const struct in6_addr*) { v }, sizeof(struct in6_addr))
#define SD_JSON_BUILD_IN_ADDR(v, f) SD_JSON_BUILD_BYTE_ARRAY(((const union in_addr_union*) { v })->bytes, FAMILY_ADDRESS_SIZE_SAFE(f))
#define SD_JSON_BUILD_ETHER_ADDR(v) SD_JSON_BUILD_BYTE_ARRAY(((const struct ether_addr*) { v })->ether_addr_octet, sizeof(struct ether_addr))
#define SD_JSON_BUILD_HW_ADDR(v) _SD_JSON_BUILD_HW_ADDR, (const struct hw_addr_data*) { v }

#define SD_JSON_BUILD_PAIR_STRING(name, s) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRING(s))
#define SD_JSON_BUILD_PAIR_INTEGER(name, i) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_INTEGER(i))
#define SD_JSON_BUILD_PAIR_UNSIGNED(name, u) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_UNSIGNED(u))
#define SD_JSON_BUILD_PAIR_REAL(name, d) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_REAL(d))
#define SD_JSON_BUILD_PAIR_BOOLEAN(name, b) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BOOLEAN(b))
#define SD_JSON_BUILD_PAIR_ARRAY(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ARRAY(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_EMPTY_ARRAY(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_EMPTY_ARRAY)
#define SD_JSON_BUILD_PAIR_OBJECT(name, ...) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_OBJECT(__VA_ARGS__))
#define SD_JSON_BUILD_PAIR_EMPTY_OBJECT(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_EMPTY_OBJECT)
#define SD_JSON_BUILD_PAIR_NULL(name) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_NULL)
#define SD_JSON_BUILD_PAIR_VARIANT(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_VARIANT(v))
#define SD_JSON_BUILD_PAIR_VARIANT_ARRAY(name, v, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_VARIANT_ARRAY(v, n))
#define SD_JSON_BUILD_PAIR_LITERAL(name, l) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_LITERAL(l))
#define SD_JSON_BUILD_PAIR_STRV(name, l) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_STRV(l))
#define SD_JSON_BUILD_PAIR_BASE64(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BASE64(p, n))
#define SD_JSON_BUILD_PAIR_HEX(name, p, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_HEX(p, n))
#define SD_JSON_BUILD_PAIR_ID128(name, id) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ID128(id))
#define SD_JSON_BUILD_PAIR_BYTE_ARRAY(name, v, n) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_BYTE_ARRAY(v, n))
#define SD_JSON_BUILD_PAIR_IN4_ADDR(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_IN4_ADDR(v))
#define SD_JSON_BUILD_PAIR_IN6_ADDR(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_IN6_ADDR(v))
#define SD_JSON_BUILD_PAIR_IN_ADDR(name, v, f) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_IN_ADDR(v, f))
#define SD_JSON_BUILD_PAIR_ETHER_ADDR(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_ETHER_ADDR(v))
#define SD_JSON_BUILD_PAIR_HW_ADDR(name, v) SD_JSON_BUILD_PAIR(name, SD_JSON_BUILD_HW_ADDR(v))

#define SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO(name, u) _SD_JSON_BUILD_PAIR_UNSIGNED_NON_ZERO, (const char*) { name }, (uint64_t) { u }
#define SD_JSON_BUILD_PAIR_FINITE_USEC(name, u) _SD_JSON_BUILD_PAIR_FINITE_USEC, (const char*) { name }, (usec_t) { u }
#define SD_JSON_BUILD_PAIR_STRING_NON_EMPTY(name, s) _SD_JSON_BUILD_PAIR_STRING_NON_EMPTY, (const char*) { name }, (const char*) { s }
#define SD_JSON_BUILD_PAIR_STRV_NON_EMPTY(name, l) _SD_JSON_BUILD_PAIR_STRV_NON_EMPTY, (const char*) { name }, (char**) { l }
#define SD_JSON_BUILD_PAIR_VARIANT_NON_NULL(name, v) _SD_JSON_BUILD_PAIR_VARIANT_NON_NULL, (const char*) { name }, (sd_json_variant*) { v }
#define SD_JSON_BUILD_PAIR_IN4_ADDR_NON_NULL(name, v) _SD_JSON_BUILD_PAIR_IN4_ADDR_NON_NULL, (const char*) { name }, (const struct in_addr*) { v }
#define SD_JSON_BUILD_PAIR_IN6_ADDR_NON_NULL(name, v) _SD_JSON_BUILD_PAIR_IN6_ADDR_NON_NULL, (const char*) { name }, (const struct in6_addr*) { v }
#define SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL(name, v, f) _SD_JSON_BUILD_PAIR_IN_ADDR_NON_NULL, (const char*) { name }, (const union in_addr_union*) { v }, (int) { f }
#define SD_JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL(name, v) _SD_JSON_BUILD_PAIR_ETHER_ADDR_NON_NULL, (const char*) { name }, (const struct ether_addr*) { v }
#define SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL(name, v) _SD_JSON_BUILD_PAIR_HW_ADDR_NON_NULL, (const char*) { name }, (const struct hw_addr_data*) { v }

int sd_json_build(sd_json_variant **ret, ...);
int sd_json_buildv(sd_json_variant **ret, va_list ap);

/* A bitmask of flags used by the dispatch logic. Note that this is a combined bit mask, that is generated from the bit
 * mask originally passed into sd_json_dispatch(), the individual bitmask associated with the static sd_json_dispatch_t callout
 * entry, as well the bitmask specified for json_log() calls */
typedef enum sd_json_dispatch_flags_t {
        /* The following three may be set in sd_json_dispatch_t's .flags field or the sd_json_dispatch() flags parameter  */
        SD_JSON_PERMISSIVE = 1 << 0, /* Shall parsing errors be considered fatal for this property? */
        SD_JSON_MANDATORY  = 1 << 1, /* Should existence of this property be mandatory? */
        SD_JSON_LOG        = 1 << 2, /* Should the parser log about errors? */
        SD_JSON_SAFE       = 1 << 3, /* Don't accept "unsafe" strings in sd_json_dispatch_string() + json_dispatch_string() */
        SD_JSON_RELAX      = 1 << 4, /* Use relaxed user name checking in json_dispatch_user_group_name */

        /* The following two may be passed into log_json() in addition to the three above */
        SD_JSON_DEBUG      = 1 << 4, /* Indicates that this log message is a debug message */
        SD_JSON_WARNING    = 1 << 5, /* Indicates that this log message is a warning message */

        _SD_ENUM_FORCE_U64(JSON_DISPATCH),
} sd_json_dispatch_flags_t;

typedef int (*sd_json_dispatch_callback_t)(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

typedef struct sd_json_dispatch_t {
        const char *name;
        sd_json_variant_type_t type;
        sd_json_dispatch_callback_t callback;
        size_t offset;
        sd_json_dispatch_flags_t flags;
} sd_json_dispatch_t;

int sd_json_dispatch(sd_json_variant *v, const sd_json_dispatch_t table[], sd_json_dispatch_callback_t bad, sd_json_dispatch_flags_t flags, void *userdata);

int sd_json_dispatch_string(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_const_string(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_strv(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_boolean(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_tristate(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_variant(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int64(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint64(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uint32(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_int32(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_uid_gid(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_user_group_name(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_id128(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);
int sd_json_dispatch_unsupported(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

#define sd_json_dispatch_uint sd_json_dispatch_uint32
#define sd_json_dispatch_int sd_json_dispatch_int32

#define SD_JSON_VARIANT_STRING_CONST(x) _SD_JSON_VARIANT_STRING_CONST(UNIQ, (x))

#define _SD_JSON_VARIANT_STRING_CONST(xq, x)                               \
        ({                                                              \
                _align_(2) static const char UNIQ_T(json_string_const, xq)[] = (x); \
                assert((((uintptr_t) UNIQ_T(json_string_const, xq)) & 1) == 0); \
                (sd_json_variant*) ((uintptr_t) UNIQ_T(json_string_const, xq) + 1); \
        })

int sd_json_variant_unbase64(sd_json_variant *v, void **ret, size_t *ret_size);
int sd_json_variant_unhex(sd_json_variant *v, void **ret, size_t *ret_size);

const char *sd_json_variant_type_to_string(sd_json_variant_type_t t);
sd_json_variant_type_t sd_json_variant_type_from_string(const char *s);
