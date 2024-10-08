// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE LibQYRA Test Suite

#include <test.h>

#include <boost/test/included/unit_test.hpp> // IWYU pragma: keep
#include <vector>

BasicTestingSetup::BasicTestingSetup()
{
    originalData = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
}

ExtendedTestingSetup::ExtendedTestingSetup()
    : BasicTestingSetup()
{
}