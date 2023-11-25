/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright (c) 2017 Oracle and/or its affiliates.  All rights reserved.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "e_os.h"
#include "testutil.h"

#define TEST(expected, test) test_case((expected), #test, (test))

static int test_case(int expected, const char *test, int result)
{
    if (result != expected) {
        fprintf(stderr, "FATAL: %s != %d\n", test, expected);
        return 0;
    }
    return 1;
}

static int test_int(void)
{
    if (!TEST(1, TEST_int_eq(1, 1))
        | !TEST(0, TEST_int_eq(1, -1))
        | !TEST(1, TEST_int_ne(1, 2))
        | !TEST(0, TEST_int_ne(3, 3))
        | !TEST(1, TEST_int_lt(4, 9))
        | !TEST(0, TEST_int_lt(9, 4))
        | !TEST(1, TEST_int_le(4, 9))
        | !TEST(1, TEST_int_le(5, 5))
        | !TEST(0, TEST_int_le(9, 4))
        | !TEST(1, TEST_int_gt(8, 5))
        | !TEST(0, TEST_int_gt(5, 8))
        | !TEST(1, TEST_int_ge(8, 5))
        | !TEST(1, TEST_int_ge(6, 6))
        | !TEST(0, TEST_int_ge(5, 8)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_uint(void)
{
    if (!TEST(1, TEST_uint_eq(3u, 3u))
        | !TEST(0, TEST_uint_eq(3u, 5u))
        | !TEST(1, TEST_uint_ne(4u, 2u))
        | !TEST(0, TEST_uint_ne(6u, 6u))
        | !TEST(1, TEST_uint_lt(5u, 9u))
        | !TEST(0, TEST_uint_lt(9u, 5u))
        | !TEST(1, TEST_uint_le(5u, 9u))
        | !TEST(1, TEST_uint_le(7u, 7u))
        | !TEST(0, TEST_uint_le(9u, 5u))
        | !TEST(1, TEST_uint_gt(11u, 1u))
        | !TEST(0, TEST_uint_gt(1u, 11u))
        | !TEST(1, TEST_uint_ge(11u, 1u))
        | !TEST(1, TEST_uint_ge(6u, 6u))
        | !TEST(0, TEST_uint_ge(1u, 11u)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_char(void)
{
    if (!TEST(1, TEST_char_eq('a', 'a'))
        | !TEST(0, TEST_char_eq('a', 'A'))
        | !TEST(1, TEST_char_ne('a', 'c'))
        | !TEST(0, TEST_char_ne('e', 'e'))
        | !TEST(1, TEST_char_lt('i', 'x'))
        | !TEST(0, TEST_char_lt('x', 'i'))
        | !TEST(1, TEST_char_le('i', 'x'))
        | !TEST(1, TEST_char_le('n', 'n'))
        | !TEST(0, TEST_char_le('x', 'i'))
        | !TEST(1, TEST_char_gt('w', 'n'))
        | !TEST(0, TEST_char_gt('n', 'w'))
        | !TEST(1, TEST_char_ge('w', 'n'))
        | !TEST(1, TEST_char_ge('p', 'p'))
        | !TEST(0, TEST_char_ge('n', 'w')))
        goto err;
    return 1;

err:
    return 0;
}

static int test_uchar(void)
{
    if (!TEST(1, TEST_uchar_eq(49, 49))
        | !TEST(0, TEST_uchar_eq(49, 60))
        | !TEST(1, TEST_uchar_ne(50, 2))
        | !TEST(0, TEST_uchar_ne(66, 66))
        | !TEST(1, TEST_uchar_lt(60, 80))
        | !TEST(0, TEST_uchar_lt(80, 60))
        | !TEST(1, TEST_uchar_le(60, 80))
        | !TEST(1, TEST_uchar_le(78, 78))
        | !TEST(0, TEST_uchar_le(80, 60))
        | !TEST(1, TEST_uchar_gt(88, 37))
        | !TEST(0, TEST_uchar_gt(37, 88))
        | !TEST(1, TEST_uchar_ge(88, 37))
        | !TEST(1, TEST_uchar_ge(66, 66))
        | !TEST(0, TEST_uchar_ge(37, 88)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_long(void)
{
    if (!TEST(1, TEST_long_eq(123l, 123l))
        | !TEST(0, TEST_long_eq(123l, -123l))
        | !TEST(1, TEST_long_ne(123l, 500l))
        | !TEST(0, TEST_long_ne(1000l, 1000l))
        | !TEST(1, TEST_long_lt(-8923l, 102934563l))
        | !TEST(0, TEST_long_lt(102934563l, -8923l))
        | !TEST(1, TEST_long_le(-8923l, 102934563l))
        | !TEST(1, TEST_long_le(12345l, 12345l))
        | !TEST(0, TEST_long_le(102934563l, -8923l))
        | !TEST(1, TEST_long_gt(84325677l, 12345l))
        | !TEST(0, TEST_long_gt(12345l, 84325677l))
        | !TEST(1, TEST_long_ge(84325677l, 12345l))
        | !TEST(1, TEST_long_ge(465869l, 465869l))
        | !TEST(0, TEST_long_ge(12345l, 84325677l)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_ulong(void)
{
    if (!TEST(1, TEST_ulong_eq(919ul, 919ul))
        | !TEST(0, TEST_ulong_eq(919ul, 10234ul))
        | !TEST(1, TEST_ulong_ne(8190ul, 66ul))
        | !TEST(0, TEST_ulong_ne(10555ul, 10555ul))
        | !TEST(1, TEST_ulong_lt(10234ul, 1000000ul))
        | !TEST(0, TEST_ulong_lt(1000000ul, 10234ul))
        | !TEST(1, TEST_ulong_le(10234ul, 1000000ul))
        | !TEST(1, TEST_ulong_le(100000ul, 100000ul))
        | !TEST(0, TEST_ulong_le(1000000ul, 10234ul))
        | !TEST(1, TEST_ulong_gt(100000000ul, 22ul))
        | !TEST(0, TEST_ulong_gt(22ul, 100000000ul))
        | !TEST(1, TEST_ulong_ge(100000000ul, 22ul))
        | !TEST(1, TEST_ulong_ge(10555ul, 10555ul))
        | !TEST(0, TEST_ulong_ge(22ul, 100000000ul)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_size_t(void)
{
    if (!TEST(1, TEST_int_eq((size_t)10, (size_t)10))
        | !TEST(0, TEST_int_eq((size_t)10, (size_t)12))
        | !TEST(1, TEST_int_ne((size_t)10, (size_t)12))
        | !TEST(0, TEST_int_ne((size_t)24, (size_t)24))
        | !TEST(1, TEST_int_lt((size_t)30, (size_t)88))
        | !TEST(0, TEST_int_lt((size_t)88, (size_t)30))
        | !TEST(1, TEST_int_le((size_t)30, (size_t)88))
        | !TEST(1, TEST_int_le((size_t)33, (size_t)33))
        | !TEST(0, TEST_int_le((size_t)88, (size_t)30))
        | !TEST(1, TEST_int_gt((size_t)52, (size_t)33))
        | !TEST(0, TEST_int_gt((size_t)33, (size_t)52))
        | !TEST(1, TEST_int_ge((size_t)52, (size_t)33))
        | !TEST(1, TEST_int_ge((size_t)38, (size_t)38))
        | !TEST(0, TEST_int_ge((size_t)33, (size_t)52)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_pointer(void)
{
    int x = 0;
    char y = 1;

    if (!TEST(1, TEST_ptr(&y))
        | !TEST(0, TEST_ptr(NULL))
        | !TEST(0, TEST_ptr_null(&y))
        | !TEST(1, TEST_ptr_null(NULL))
        | !TEST(1, TEST_ptr_eq(NULL, NULL))
        | !TEST(0, TEST_ptr_eq(NULL, &y))
        | !TEST(0, TEST_ptr_eq(&y, NULL))
        | !TEST(0, TEST_ptr_eq(&y, &x))
        | !TEST(1, TEST_ptr_eq(&x, &x))
        | !TEST(0, TEST_ptr_ne(NULL, NULL))
        | !TEST(1, TEST_ptr_ne(NULL, &y))
        | !TEST(1, TEST_ptr_ne(&y, NULL))
        | !TEST(1, TEST_ptr_ne(&y, &x))
        | !TEST(0, TEST_ptr_ne(&x, &x)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_bool(void)
{
    if (!TEST(0, TEST_true(0))
        | !TEST(1, TEST_true(1))
        | !TEST(1, TEST_false(0))
        | !TEST(0, TEST_false(1)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_string(void)
{
    static char buf[] = "abc";

    if (!TEST(1, TEST_str_eq(NULL, NULL))
        | !TEST(1, TEST_str_eq("abc", buf))
        | !TEST(0, TEST_str_eq("abc", NULL))
        | !TEST(0, TEST_str_eq(NULL, buf))
        | !TEST(0, TEST_str_ne(NULL, NULL))
        | !TEST(0, TEST_str_ne("abc", buf))
        | !TEST(1, TEST_str_ne("abc", NULL))
        | !TEST(1, TEST_str_ne(NULL, buf)))
        goto err;
    return 1;

err:
    return 0;
}

static int test_memory(void)
{
    static char buf[] = "xyz";

    if (!TEST(1, TEST_mem_eq(NULL, 0, NULL, 0))
        | !TEST(1, TEST_mem_eq(NULL, 1, NULL, 2))
        | !TEST(0, TEST_mem_eq(NULL, 0, "xyz", 3))
        | !TEST(0, TEST_mem_eq(NULL, 0, "", 0))
        | !TEST(0, TEST_mem_eq("xyz", 3, NULL, 0))
        | !TEST(0, TEST_mem_eq("xyz", 3, buf, sizeof(buf)))
        | !TEST(1, TEST_mem_eq("xyz", 4, buf, sizeof(buf))))
        goto err;
    return 1;

err:
    return 0;
}

static int test_memory_overflow(void)
{
    /* Verify that the memory printing overflows without walking the stack */
    const char *p = "1234567890123456789012345678901234567890123456789012";
    const char *q = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    return TEST(0, TEST_mem_eq(p, strlen(p), q, strlen(q)));
}

static int test_messages(void)
{
    TEST_info("This is an %s message.", "info");
    TEST_error("This is an %s message.", "error");
    return 1;
}

static int test_single_eval(void)
{
    int i = 4;
    long l = -9000;
    char c = 'd';
    unsigned char uc = 22;
    unsigned long ul = 500;
    size_t st = 1234;
    char buf[4] = { 0 }, *p = buf;

           /* int */
    return TEST_int_eq(i++, 4)
           && TEST_int_eq(i, 5)
           && TEST_int_gt(++i, 5)
           && TEST_int_le(5, i++)
           && TEST_int_ne(--i, 5)
           && TEST_int_eq(12, i *= 2)
           /* Long */
           && TEST_long_eq(l--, -9000L)
           && TEST_long_eq(++l, -9000L)
           && TEST_long_ne(-9000L, l /= 2)
           && TEST_long_lt(--l, -4500L)
           /* char */
           && TEST_char_eq(++c, 'e')
           && TEST_char_eq('e', c--)
           && TEST_char_ne('d', --c)
           && TEST_char_le('b', --c)
           && TEST_char_lt(c++, 'c')
           /* unsigned char */
           && TEST_uchar_eq(22, uc++)
           && TEST_uchar_eq(uc /= 2, 11)
           && TEST_ulong_eq(ul ^= 1, 501)
           && TEST_ulong_eq(502, ul ^= 3)
           && TEST_ulong_eq(ul = ul * 3 - 6, 1500)
           /* size_t */
           && TEST_size_t_eq((--i, st++), 1234)
           && TEST_size_t_eq(st, 1235)
           && TEST_int_eq(11, i)
           /* pointers */
           && TEST_ptr_eq(p++, buf)
           && TEST_ptr_eq(buf + 2, ++p)
           && TEST_ptr_eq(buf, p -= 2)
           && TEST_ptr(++p)
           && TEST_ptr_eq(p, buf + 1)
           && TEST_ptr_null(p = NULL)
           /* strings */
           && TEST_str_eq(p = "123456" + 1, "23456")
           && TEST_str_eq("3456", ++p)
           && TEST_str_ne(p++, "456")
           /* memory */
           && TEST_mem_eq(--p, sizeof("3456"), "3456", sizeof("3456"))
           && TEST_mem_ne(p++, sizeof("456"), "456", sizeof("456"))
           && TEST_mem_eq(p--, sizeof("456"), "456", sizeof("456"));
}

void register_tests(void)
{
    ADD_TEST(test_int);
    ADD_TEST(test_uint);
    ADD_TEST(test_char);
    ADD_TEST(test_uchar);
    ADD_TEST(test_long);
    ADD_TEST(test_ulong);
    ADD_TEST(test_size_t);
    ADD_TEST(test_pointer);
    ADD_TEST(test_bool);
    ADD_TEST(test_string);
    ADD_TEST(test_memory);
    ADD_TEST(test_memory_overflow);
    ADD_TEST(test_messages);
    ADD_TEST(test_single_eval);
}
