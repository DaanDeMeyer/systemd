/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <float.h>
#include <math.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "json-internal.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "util.h"

static void test_tokenizer_one(const char *data, ...) {
        unsigned line = 0, column = 0;
        void *state = NULL;
        va_list ap;

        _cleanup_free_ char *cdata;
        assert_se(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        va_start(ap, data);

        for (;;) {
                unsigned token_line, token_column;
                _cleanup_free_ char *str = NULL;
                JsonValue v = JSON_VALUE_NULL;
                int t, tt;

                t = json_tokenize(&data, &str, &v, &token_line, &token_column, &state, &line, &column);
                tt = va_arg(ap, int);

                assert_se(t == tt);

                if (t == JSON_TOKEN_END || t < 0)
                        break;

                else if (t == JSON_TOKEN_STRING) {
                        const char *nn;

                        nn = va_arg(ap, const char *);
                        assert_se(streq_ptr(nn, str));

                } else if (t == JSON_TOKEN_REAL) {
                        double d;

                        d = va_arg(ap, double);

                        assert_se(fabsl(d - v.real) < 1e-10 ||
                                  fabsl((d - v.real) / v.real) < 1e-10);

                } else if (t == JSON_TOKEN_INTEGER) {
                        int64_t i;

                        i = va_arg(ap, int64_t);
                        assert_se(i == v.integer);

                } else if (t == JSON_TOKEN_UNSIGNED) {
                        uint64_t u;

                        u = va_arg(ap, uint64_t);
                        assert_se(u == v.unsig);

                } else if (t == JSON_TOKEN_BOOLEAN) {
                        bool b;

                        b = va_arg(ap, int);
                        assert_se(b == v.boolean);
                }
        }

        va_end(ap);
}

typedef void (*Test)(sd_json_variant *);

static void test_variant_one(const char *data, Test test) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        _cleanup_free_ char *cdata;
        assert_se(cdata = cescape(data));
        log_info("/* %s data=\"%s\" */", __func__, cdata);

        r = sd_json_parse(data, 0, &v, NULL, NULL);
        assert_se(r == 0);
        assert_se(v);

        r = sd_json_variant_format(v, 0, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted normally: %s\n", s);

        r = sd_json_parse(data, SD_JSON_PARSE_SENSITIVE, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);
        assert_se(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        assert_se(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        assert_se(sd_json_variant_equal(v, w));

        s = mfree(s);
        w = sd_json_variant_unref(w);

        r = sd_json_variant_format(v, SD_JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));

        log_info("formatted prettily:\n%s", s);

        r = sd_json_parse(data, 0, &w, NULL, NULL);
        assert_se(r == 0);
        assert_se(w);

        assert_se(sd_json_variant_has_type(v, sd_json_variant_type(w)));
        assert_se(sd_json_variant_has_type(w, sd_json_variant_type(v)));
        assert_se(sd_json_variant_equal(v, w));

        s = mfree(s);
        r = sd_json_variant_format(v, SD_JSON_FORMAT_COLOR, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Normal with color: %s\n", s);

        s = mfree(s);
        r = sd_json_variant_format(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, &s);
        assert_se(r >= 0);
        assert_se(s);
        assert_se((size_t) r == strlen(s));
        printf("Pretty with color:\n%s\n", s);

        if (test)
                test(v);
}

static void test_1(sd_json_variant *v) {
        sd_json_variant *p, *q;
        unsigned i;

        log_info("/* %s */", __func__);

        /* 3 keys + 3 values */
        assert_se(sd_json_variant_elements(v) == 6);

        /* has k */
        p = sd_json_variant_by_key(v, "k");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_STRING);

        /* k equals v */
        assert_se(streq(sd_json_variant_string(p), "v"));

        /* has foo */
        p = sd_json_variant_by_key(v, "foo");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 3);

        /* check  foo[0] = 1, foo[1] = 2, foo[2] = 3 */
        for (i = 0; i < 3; ++i) {
                q = sd_json_variant_by_index(p, i);
                assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == (i+1));
                assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == (i+1));
        }

        /* has bar */
        p = sd_json_variant_by_key(v, "bar");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_OBJECT && sd_json_variant_elements(p) == 2);

        /* zap is null */
        q = sd_json_variant_by_key(p, "zap");
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_NULL);
}

static void test_2(sd_json_variant *v) {
        sd_json_variant *p, *q;

        log_info("/* %s */", __func__);

        /* 2 keys + 2 values */
        assert_se(sd_json_variant_elements(v) == 4);

        /* has mutant */
        p = sd_json_variant_by_key(v, "mutant");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 4);

        /* mutant[0] == 1 */
        q = sd_json_variant_by_index(p, 0);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == 1);
        assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == 1);

        /* mutant[1] == null */
        q = sd_json_variant_by_index(p, 1);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_NULL);

        /* mutant[2] == "1" */
        q = sd_json_variant_by_index(p, 2);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_STRING && streq(sd_json_variant_string(q), "1"));

        /* mutant[3] == SD_JSON_VARIANT_OBJECT */
        q = sd_json_variant_by_index(p, 3);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_OBJECT && sd_json_variant_elements(q) == 2);

        /* has 1 */
        p = sd_json_variant_by_key(q, "1");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_ARRAY && sd_json_variant_elements(p) == 2);

        /* "1"[0] == 1 */
        q = sd_json_variant_by_index(p, 0);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_UNSIGNED && sd_json_variant_unsigned(q) == 1);
        assert_se(q && sd_json_variant_has_type(q, SD_JSON_VARIANT_INTEGER) && sd_json_variant_integer(q) == 1);

        /* "1"[1] == "1" */
        q = sd_json_variant_by_index(p, 1);
        assert_se(q && sd_json_variant_type(q) == SD_JSON_VARIANT_STRING && streq(sd_json_variant_string(q), "1"));

        /* has thisisaverylongproperty */
        p = sd_json_variant_by_key(v, "thisisaverylongproperty");
        assert_se(p && sd_json_variant_type(p) == SD_JSON_VARIANT_REAL && fabsl(sd_json_variant_real(p) - 1.27) < 0.001);
}

static void test_zeroes(sd_json_variant *v) {
        /* Make sure zero is how we expect it. */
        log_info("/* %s */", __func__);

        assert_se(sd_json_variant_elements(v) == 13);

        for (size_t i = 0; i < sd_json_variant_elements(v); i++) {
                sd_json_variant *w;
                size_t j;

                assert_se(w = sd_json_variant_by_index(v, i));

                assert_se(sd_json_variant_integer(w) == 0);
                assert_se(sd_json_variant_unsigned(w) == 0U);

                DISABLE_WARNING_FLOAT_EQUAL;
                assert_se(sd_json_variant_real(w) == 0.0L);
                REENABLE_WARNING;

                assert_se(sd_json_variant_is_integer(w));
                assert_se(sd_json_variant_is_unsigned(w));
                assert_se(sd_json_variant_is_real(w));
                assert_se(sd_json_variant_is_number(w));

                assert_se(!sd_json_variant_is_negative(w));

                assert_se(IN_SET(sd_json_variant_type(w), SD_JSON_VARIANT_INTEGER, SD_JSON_VARIANT_UNSIGNED, SD_JSON_VARIANT_REAL));

                for (j = 0; j < sd_json_variant_elements(v); j++) {
                        sd_json_variant *q;

                        assert_se(q = sd_json_variant_by_index(v, j));

                        assert_se(sd_json_variant_equal(w, q));
                }
        }
}

TEST(build) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL, *b = NULL;
        _cleanup_free_ char *s = NULL, *t = NULL;

        assert_se(sd_json_build(&a, SD_JSON_BUILD_STRING("hallo")) >= 0);
        assert_se(sd_json_build(&b, SD_JSON_BUILD_LITERAL(" \"hallo\"   ")) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&b, SD_JSON_BUILD_VARIANT(a)) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        b = sd_json_variant_unref(b);
        assert_se(sd_json_build(&b, SD_JSON_BUILD_STRING("pief")) >= 0);
        assert_se(!sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&a, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_INTEGER(7)),
                                                   SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_REAL(2.0)),
                                                   SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_INTEGER(0)))) >= 0);

        assert_se(sd_json_build(&b, SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("two", SD_JSON_BUILD_INTEGER(2)),
                                                   SD_JSON_BUILD_PAIR("three", SD_JSON_BUILD_REAL(0)),
                                                   SD_JSON_BUILD_PAIR("one", SD_JSON_BUILD_REAL(7)))) >= 0);

        assert_se(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        const char* arr_1234[] = {"one", "two", "three", "four", NULL};
        assert_se(sd_json_build(&a, SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_BOOLEAN(true)),
                                                                    SD_JSON_BUILD_PAIR("y", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("this", SD_JSON_BUILD_NULL)))),
                                                  SD_JSON_BUILD_VARIANT(NULL),
                                                  SD_JSON_BUILD_LITERAL(NULL),
                                                  SD_JSON_BUILD_STRING(NULL),
                                                  SD_JSON_BUILD_NULL,
                                                  SD_JSON_BUILD_INTEGER(77),
                                                  SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(SD_JSON_VARIANT_STRING_CONST("foobar")),
                                                                   SD_JSON_BUILD_VARIANT(SD_JSON_VARIANT_STRING_CONST("zzz"))),
                                                  SD_JSON_BUILD_STRV((char**) arr_1234))) >= 0);

        assert_se(sd_json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(sd_json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(sd_json_variant_equal(a, b));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&a, SD_JSON_BUILD_REAL(M_PIl)) >= 0);

        s = mfree(s);
        assert_se(sd_json_variant_format(a, 0, &s) >= 0);
        log_info("GOT: %s\n", s);
        assert_se(sd_json_parse(s, 0, &b, NULL, NULL) >= 0);
        assert_se(sd_json_variant_format(b, 0, &t) >= 0);
        log_info("GOT: %s\n", t);

        assert_se(streq(s, t));

        a = sd_json_variant_unref(a);
        b = sd_json_variant_unref(b);

        assert_se(sd_json_build(&a, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR("z", SD_JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(sd_json_build(&b, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("x", SD_JSON_BUILD_STRING("y")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "p", SD_JSON_BUILD_STRING("q")),
                                             SD_JSON_BUILD_PAIR_CONDITION(true, "z", SD_JSON_BUILD_CONST_STRING("a")),
                                             SD_JSON_BUILD_PAIR_CONDITION(false, "j", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_STRING("k"), SD_JSON_BUILD_CONST_STRING("u"), SD_JSON_BUILD_CONST_STRING("i"))),
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_CONST_STRING("c"))
                             )) >= 0);

        assert_se(sd_json_variant_equal(a, b));
}

TEST(source) {
        static const char data[] =
                "\n"
                "\n"
                "{\n"
                "\"foo\" : \"bar\", \n"
                "\"qüüx\" : [ 1, 2, 3,\n"
                "4,\n"
                "5 ],\n"
                "\"miep\" : { \"hallo\" : 1 },\n"
                "\n"
                "\"zzzzzz\" \n"
                ":\n"
                "[ true, \n"
                "false, 7.5, {} ]\n"
                "}\n";

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        printf("--- original begin ---\n"
               "%s"
               "--- original end ---\n", data);

        assert_se(f = fmemopen_unlocked((void*) data, strlen(data), "r"));

        assert_se(sd_json_parse_file(f, "waldo", 0, &v, NULL, NULL) >= 0);

        printf("--- non-pretty begin ---\n");
        sd_json_variant_dump(v, 0, stdout, NULL);
        printf("\n--- non-pretty end ---\n");

        printf("--- pretty begin ---\n");
        sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_SOURCE, stdout, NULL);
        printf("--- pretty end ---\n");
}

TEST(depth) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        v = SD_JSON_VARIANT_STRING_CONST("start");

        /* Let's verify that the maximum depth checks work */

        for (unsigned i = 0;; i++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

                assert_se(i <= UINT16_MAX);
                if (i & 1)
                        r = sd_json_variant_new_array(&w, &v, 1);
                else
                        r = sd_json_variant_new_object(&w, (sd_json_variant*[]) { SD_JSON_VARIANT_STRING_CONST("key"), v }, 2);
                if (r == -ELNRNG) {
                        log_info("max depth at %u", i);
                        break;
                }
#if HAS_FEATURE_MEMORY_SANITIZER
                /* msan doesn't like the stack nesting to be too deep. Let's quit early. */
                if (i >= 128) {
                        log_info("quitting early at depth %u", i);
                        break;
                }
#endif

                assert_se(r >= 0);

                sd_json_variant_unref(v);
                v = TAKE_PTR(w);
        }

        sd_json_variant_dump(v, 0, stdout, NULL);
        fputs("\n", stdout);
}

TEST(normalize) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *t = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("c", SD_JSON_BUILD_CONST_STRING("y")),
                                             SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_CONST_STRING("z")))) >= 0);

        assert_se(!sd_json_variant_is_sorted(v));
        assert_se(!sd_json_variant_is_normalized(v));

        assert_se(sd_json_variant_format(v, 0, &t) >= 0);
        assert_se(streq(t, "{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}"));
        t = mfree(t);

        assert_se(sd_json_build(&w, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("bar", SD_JSON_BUILD_STRING("zzz")),
                                             SD_JSON_BUILD_PAIR("foo", SD_JSON_BUILD_VARIANT(v)))) >= 0);

        assert_se(sd_json_variant_is_sorted(w));
        assert_se(!sd_json_variant_is_normalized(w));

        assert_se(sd_json_variant_format(w, 0, &t) >= 0);
        assert_se(streq(t, "{\"bar\":\"zzz\",\"foo\":{\"b\":\"x\",\"c\":\"y\",\"a\":\"z\"}}"));
        t = mfree(t);

        assert_se(sd_json_variant_sort(&v) >= 0);
        assert_se(sd_json_variant_is_sorted(v));
        assert_se(sd_json_variant_is_normalized(v));

        assert_se(sd_json_variant_format(v, 0, &t) >= 0);
        assert_se(streq(t, "{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}"));
        t = mfree(t);

        assert_se(sd_json_variant_normalize(&w) >= 0);
        assert_se(sd_json_variant_is_sorted(w));
        assert_se(sd_json_variant_is_normalized(w));

        assert_se(sd_json_variant_format(w, 0, &t) >= 0);
        assert_se(streq(t, "{\"bar\":\"zzz\",\"foo\":{\"a\":\"z\",\"b\":\"x\",\"c\":\"y\"}}"));
        t = mfree(t);
}

TEST(bisect) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        /* Tests the bisection logic in sd_json_variant_by_key() */

        for (char c = 'z'; c >= 'a'; c--) {

                if ((c % 3) == 0)
                        continue;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
                assert_se(sd_json_variant_new_stringn(&w, (char[4]) { '<', c, c, '>' }, 4) >= 0);
                assert_se(sd_json_variant_set_field(&v, (char[2]) { c, 0 }, w) >= 0);
        }

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        assert_se(!sd_json_variant_is_sorted(v));
        assert_se(!sd_json_variant_is_normalized(v));
        assert_se(sd_json_variant_normalize(&v) >= 0);
        assert_se(sd_json_variant_is_sorted(v));
        assert_se(sd_json_variant_is_normalized(v));

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        for (char c = 'a'; c <= 'z'; c++) {
                sd_json_variant *k;
                const char *z;

                k = sd_json_variant_by_key(v, (char[2]) { c, 0 });
                assert_se(!k == ((c % 3) == 0));

                if (!k)
                        continue;

                assert_se(sd_json_variant_is_string(k));

                z = (char[5]){ '<', c, c, '>', 0};
                assert_se(streq(sd_json_variant_string(k), z));
        }
}

static void test_float_match(sd_json_variant *v) {
        const double delta = 0.0001;

        assert_se(sd_json_variant_is_array(v));
        assert_se(sd_json_variant_elements(v) == 9);
        assert_se(fabsl((double) 1.0 - ((double) DBL_MIN / sd_json_variant_real(sd_json_variant_by_index(v, 0)))) <= delta);
        assert_se(fabsl((double) 1.0 - ((double) DBL_MAX / sd_json_variant_real(sd_json_variant_by_index(v, 1)))) <= delta);
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 2))); /* nan is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 3))); /* +inf is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 4))); /* -inf is not supported by json → null */
        assert_se(sd_json_variant_is_null(sd_json_variant_by_index(v, 5)) ||
                  fabsl((double) 1.0 - ((double) HUGE_VAL / sd_json_variant_real(sd_json_variant_by_index(v, 5)))) <= delta); /* HUGE_VAL might be +inf, but might also be something else */
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 6)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 6)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 6)) == 0);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 7)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 7)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 7)) == 10);
        assert_se(sd_json_variant_is_real(sd_json_variant_by_index(v, 8)) &&
                  sd_json_variant_is_integer(sd_json_variant_by_index(v, 8)) &&
                  sd_json_variant_integer(sd_json_variant_by_index(v, 8)) == -10);
}

TEST(float) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        _cleanup_free_ char *text = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_ARRAY(
                                             SD_JSON_BUILD_REAL(DBL_MIN),
                                             SD_JSON_BUILD_REAL(DBL_MAX),
                                             SD_JSON_BUILD_REAL(NAN),
                                             SD_JSON_BUILD_REAL(INFINITY),
                                             SD_JSON_BUILD_REAL(-INFINITY),
                                             SD_JSON_BUILD_REAL(HUGE_VAL),
                                             SD_JSON_BUILD_REAL(0),
                                             SD_JSON_BUILD_REAL(10),
                                             SD_JSON_BUILD_REAL(-10))) >= 0);

        sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(v);

        assert_se(sd_json_variant_format(v, 0, &text) >= 0);
        assert_se(sd_json_parse(text, 0, &w, NULL, NULL) >= 0);

        sd_json_variant_dump(w, SD_JSON_FORMAT_COLOR|SD_JSON_FORMAT_PRETTY, NULL, NULL);

        test_float_match(w);
}

static void test_equal_text(sd_json_variant *v, const char *text) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;

        assert_se(sd_json_parse(text, 0, &w, NULL, NULL) >= 0);
        assert_se(sd_json_variant_equal(v, w) || (!v && sd_json_variant_is_null(w)));
}

TEST(set_field) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        test_equal_text(v, "null");
        assert_se(sd_json_variant_set_field(&v, "foo", NULL) >= 0);
        test_equal_text(v, "{\"foo\" : null}");
        assert_se(sd_json_variant_set_field(&v, "bar", SD_JSON_VARIANT_STRING_CONST("quux")) >= 0);
        test_equal_text(v, "{\"foo\" : null, \"bar\" : \"quux\"}");
        assert_se(sd_json_variant_set_field(&v, "foo", SD_JSON_VARIANT_STRING_CONST("quux2")) >= 0);
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : \"quux\"}");
        assert_se(sd_json_variant_set_field(&v, "bar", NULL) >= 0);
        test_equal_text(v, "{\"foo\" : \"quux2\", \"bar\" : null}");
}

TEST(tokenizer) {
        test_tokenizer_one("x", -EINVAL);
        test_tokenizer_one("", JSON_TOKEN_END);
        test_tokenizer_one(" ", JSON_TOKEN_END);
        test_tokenizer_one("0", JSON_TOKEN_UNSIGNED, (uint64_t) 0, JSON_TOKEN_END);
        test_tokenizer_one("-0", JSON_TOKEN_INTEGER, (int64_t) 0, JSON_TOKEN_END);
        test_tokenizer_one("1234", JSON_TOKEN_UNSIGNED, (uint64_t) 1234, JSON_TOKEN_END);
        test_tokenizer_one("-1234", JSON_TOKEN_INTEGER, (int64_t) -1234, JSON_TOKEN_END);
        test_tokenizer_one("18446744073709551615", JSON_TOKEN_UNSIGNED, (uint64_t) UINT64_MAX, JSON_TOKEN_END);
        test_tokenizer_one("-9223372036854775808", JSON_TOKEN_INTEGER, (int64_t) INT64_MIN, JSON_TOKEN_END);
        test_tokenizer_one("18446744073709551616", JSON_TOKEN_REAL, (double) 18446744073709551616.0L, JSON_TOKEN_END);
        test_tokenizer_one("-9223372036854775809", JSON_TOKEN_REAL, (double) -9223372036854775809.0L, JSON_TOKEN_END);
        test_tokenizer_one("-1234", JSON_TOKEN_INTEGER, (int64_t) -1234, JSON_TOKEN_END);
        test_tokenizer_one("3.141", JSON_TOKEN_REAL, (double) 3.141, JSON_TOKEN_END);
        test_tokenizer_one("0.0", JSON_TOKEN_REAL, (double) 0.0, JSON_TOKEN_END);
        test_tokenizer_one("7e3", JSON_TOKEN_REAL, (double) 7e3, JSON_TOKEN_END);
        test_tokenizer_one("-7e-3", JSON_TOKEN_REAL, (double) -7e-3, JSON_TOKEN_END);
        test_tokenizer_one("true", JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_END);
        test_tokenizer_one("false", JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_END);
        test_tokenizer_one("null", JSON_TOKEN_NULL, JSON_TOKEN_END);
        test_tokenizer_one("{}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\t {\n} \n", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("[]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\t [] \n\n", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\"\"", JSON_TOKEN_STRING, "", JSON_TOKEN_END);
        test_tokenizer_one("\"foo\"", JSON_TOKEN_STRING, "foo", JSON_TOKEN_END);
        test_tokenizer_one("\"foo\\nfoo\"", JSON_TOKEN_STRING, "foo\nfoo", JSON_TOKEN_END);
        test_tokenizer_one("{\"foo\" : \"bar\"}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_STRING, "bar", JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("{\"foo\" : [true, false]}", JSON_TOKEN_OBJECT_OPEN, JSON_TOKEN_STRING, "foo", JSON_TOKEN_COLON, JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_BOOLEAN, true, JSON_TOKEN_COMMA, JSON_TOKEN_BOOLEAN, false, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_OBJECT_CLOSE, JSON_TOKEN_END);
        test_tokenizer_one("\"\xef\xbf\xbd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer_one("\"\\ufffd\"", JSON_TOKEN_STRING, "\xef\xbf\xbd", JSON_TOKEN_END);
        test_tokenizer_one("\"\\uf\"", -EINVAL);
        test_tokenizer_one("\"\\ud800a\"", -EINVAL);
        test_tokenizer_one("\"\\udc00\\udc00\"", -EINVAL);
        test_tokenizer_one("\"\\ud801\\udc37\"", JSON_TOKEN_STRING, "\xf0\x90\x90\xb7", JSON_TOKEN_END);

        test_tokenizer_one("[1, 2, -3]", JSON_TOKEN_ARRAY_OPEN, JSON_TOKEN_UNSIGNED, (uint64_t) 1, JSON_TOKEN_COMMA, JSON_TOKEN_UNSIGNED, (uint64_t) 2, JSON_TOKEN_COMMA, JSON_TOKEN_INTEGER, (int64_t) -3, JSON_TOKEN_ARRAY_CLOSE, JSON_TOKEN_END);
}

TEST(variant) {
        test_variant_one("{\"k\": \"v\", \"foo\": [1, 2, 3], \"bar\": {\"zap\": null}}", test_1);
        test_variant_one("{\"mutant\": [1, null, \"1\", {\"1\": [1, \"1\"]}], \"thisisaverylongproperty\": 1.27}", test_2);
        test_variant_one("{\"foo\" : \"\\u0935\\u093f\\u0935\\u0947\\u0915\\u0916\\u094d\\u092f\\u093e\\u0924\\u093f\\u0930\\u0935\\u093f\\u092a\\u094d\\u0932\\u0935\\u093e\\u0020\\u0939\\u093e\\u0928\\u094b\\u092a\\u093e\\u092f\\u0903\\u0964\"}", NULL);

        test_variant_one("[ 0, -0, 0.0, -0.0, 0.000, -0.000, 0e0, -0e0, 0e+0, -0e-0, 0e-0, -0e000, 0e+000 ]", test_zeroes);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
