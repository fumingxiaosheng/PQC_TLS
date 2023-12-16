/*
 * WARNING: do not edit!
 * Generated by statistics/bn_rand_range.py in the OpenSSL tool repository.
 *
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

static const struct {
    unsigned int range;
    unsigned int iterations;
    double critical;
} rand_range_cases[] = {
    {     2,     200,     3.841459 },
    {     3,     300,     5.991465 },
    {     4,     400,     7.814728 },
    {     5,     500,     9.487729 },
    {     6,     600,    11.070498 },
    {     7,     700,    12.591587 },
    {     8,     800,    14.067140 },
    {     9,     900,    15.507313 },
    {    10,    1000,    16.918978 },
    {    11,    1100,    18.307038 },
    {    12,    1200,    19.675138 },
    {    13,    1300,    21.026070 },
    {    14,    1400,    22.362032 },
    {    15,    1500,    23.684791 },
    {    16,    1600,    24.995790 },
    {    17,    1700,    26.296228 },
    {    18,    1800,    27.587112 },
    {    19,    1900,    28.869299 },
    {    20,    2000,    30.143527 },
    {    30,    3000,    42.556968 },
    {    40,    4000,    54.572228 },
    {    50,    5000,    66.338649 },
    {    60,    6000,    77.930524 },
    {    70,    7000,    89.391208 },
    {    80,    8000,   100.748619 },
    {    90,    9000,   112.021986 },
    {   100,   10000,   123.225221 },
    {  1000,   10000,  1073.642651 },
    {  2000,   20000,  2104.128222 },
    {  3000,   30000,  3127.515432 },
    {  4000,   40000,  4147.230012 },
    {  5000,   50000,  5164.598069 },
    {  6000,   60000,  6180.299514 },
    {  7000,   70000,  7194.738181 },
    {  8000,   80000,  8208.177159 },
    {  9000,   90000,  9220.799176 },
    { 10000,  100000, 10232.737266 },
};

static const int binomial_critical = 29;

