//
// Created by 20264 on 2024/7/1.
//

// 三方库

#include <catch2/catch_assertion_result.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cstdio>
#include <cstdlib>
#include <spdlog/spdlog.h>

// 标准库
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

// 系统库
#include <Windows.h>

#include <WinBase.h>
#include <vector>
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
        MAKEINTRESOURCE(PEFileMain), RT_RCDATA);

    REQUIRE(hrsrc != 0);

    auto load_res = LoadResource(nullptr, hrsrc);
    LockResource(load_res);

    auto size = SizeofResource(nullptr, hrsrc);

    REQUIRE(size > 0);
    std::unique_ptr<uint8_t[]> buf { new uint8_t[size] };

    memcpy(buf.get(), load_res, size);

    std::stringstream fp;
    fp.write((char*)buf.get(), size);

    // std::ifstream fp { R"(C:\Windows\System32\notepad.exe)" };

    SECTION("DOS头")
    {
        auto h = PEFile::readHeader<IMAGE_DOS_HEADER>(fp);

        uint8_t MZ[] = { 'M', 'Z' };
        REQUIRE(h.e_magic == *(uint16_t*)&MZ);
    }

    SECTION("PE标记")
    {
        uint8_t PE[] = { 'P', 'E' };
        REQUIRE(PEFile::readPEMarker(fp) == (*(uint16_t*)&PE));
    }

    SECTION("标准PE头")
    {
        auto h = PEFile::readHeader<IMAGE_FILE_HEADER>(fp);

        // 0x8664
        REQUIRE((size_t)h.Machine == IMAGE_FILE_MACHINE_AMD64);
        // 0x22
        REQUIRE(h.Characteristics == //
            (IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_EXECUTABLE_IMAGE));
    }

    SECTION("扩展PE头")
    {
        auto h = PEFile::readHeader<IMAGE_OPTIONAL_HEADER64>(fp);

        REQUIRE((size_t)h.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        REQUIRE(h.FileAlignment == 0x200);
        REQUIRE(h.SectionAlignment == 0x1000);
        REQUIRE(h.SizeOfCode % h.FileAlignment == 0);
        REQUIRE(h.SectionAlignment >= h.FileAlignment);
        REQUIRE(h.SizeOfImage % h.SectionAlignment == 0);
        REQUIRE(h.SizeOfHeaders == 0x400);

        // 0x8160
        // 0xc160
        // REQUIRE((size_t)h.DllCharacteristics == //
        //     (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE // 0x8000
        //         | IMAGE_DLLCHARACTERISTICS_NX_COMPAT // 0x0100
        //         | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE // 0x0040
        //         | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)); // 0x0020
    }

    SECTION("节表")
    {
        auto size = PEFile::readHeader<IMAGE_FILE_HEADER>(fp).NumberOfSections;

        auto h = PEFile::readHeader<IMAGE_OPTIONAL_HEADER64>(fp);

        auto sections = PEFile::sectionTable(fp);

        // 拿到fp的当前位置
        auto pos = fp.tellg();
        REQUIRE(pos <= h.SizeOfHeaders);

        for (auto i = 0; i < size; i++) {
            auto& section = sections[i];
        }
    }

    SECTION("文件转换到镜像")
    {
        auto size = PEFile::sizeofImage(fp);
        auto image = PEFile::fileToImage(fp);

        // relative address = target address - (current address + instruction length)

        const char(&str)[659456] = (const char(&)[659456]) * image.data();

        std::stringstream image_fp(std::string(image.begin(), image.end()));
        image_fp.write((char*)image.data(), image.size());

        auto n = PEFile::readHeader<IMAGE_FILE_HEADER>(image_fp).NumberOfSections;
        auto sections = PEFile::sectionTable(image_fp);

        REQUIRE(image.size() == size);

        fp.seekg(0, std::ios::end);
        std::vector<uint8_t> file_buffer(fp.tellg());

        PEFile::imageToFile(image, file_buffer, 0);

        auto file = std::string { (char*)file_buffer.data(), file_buffer.size() };

        REQUIRE(file == fp.str());

        // file_buffer 写入new.exe
        std::ofstream new_exe { R"(new.exe)" };
        new_exe.write((char*)file_buffer.data(), file_buffer.size());
    }
}
