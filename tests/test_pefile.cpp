//
// Created by 20264 on 2024/7/1.
//

// 三方库

#include <catch2/catch_assertion_result.hpp>
#include <catch2/catch_test_macros.hpp>
#include <fmt/format.h>

// 标准库
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>

// 系统库
#include <Windows.h>

#include <WinBase.h>
#include <winnt.h>

// 项目头
#include "pefile.h"
#include "test_pefile_resource.h"

TEST_CASE("测试DOS IMAGE 大小")
{
    REQUIRE(sizeof(IMAGE_DOS_HEADER) == 64);
}

TEST_CASE("读取PE x64")
{
    auto hrsrc = FindResource(
        nullptr,
        MAKEINTRESOURCE(PEFileRC), RT_RCDATA);

    REQUIRE(hrsrc != 0);

    auto load_res = LoadResource(nullptr, hrsrc);
    LockResource(load_res);

    auto size = SizeofResource(nullptr, hrsrc);

    REQUIRE(size > 0);
    std::unique_ptr<uint8_t[]> buf { new uint8_t[size] };

    memcpy(buf.get(), load_res, size);

    std::stringstream fp;
    fp.write((char*)buf.get(), size);

    SECTION("DOS头")
    {

        fp.seekg(0);
        auto h = PEFile::readHeader<IMAGE_DOS_HEADER>(fp);

        uint8_t MZ[] = { 'M', 'Z' };
        REQUIRE(h.e_magic == *(uint16_t*)&MZ);
        REQUIRE(h.e_lfanew == 248);
    }
}
