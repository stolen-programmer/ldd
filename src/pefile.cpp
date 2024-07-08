//
// Created by 20264 on 2024/7/1.
//

// 三方库
#include <cstring>
#include <spdlog/spdlog.h>

// 标准头
#include <cstdint>
#include <memory>
#include <sstream>
#include <utility>

// 系统头
#include <Windows.h>
#include <vector>
#include <winnt.h>

// 项目头
#include "pefile.h"

auto PEFile::readPEMarker(std::istream& fp) -> DWORD
{
    auto dos_h = readHeader<IMAGE_DOS_HEADER>(fp);

    DWORD Signature; // PE 标记
    fp.seekg(dos_h.e_lfanew);
    fp.read((char*)&Signature, sizeof(Signature));

    return Signature;
}

template <>
IMAGE_FILE_HEADER PEFile::readHeader<IMAGE_FILE_HEADER>(std::istream& fp)
{
    auto dos_h = readHeader<IMAGE_DOS_HEADER>(fp);

    fp.seekg(dos_h.e_lfanew + 4);

    IMAGE_FILE_HEADER h;
    fp.read((char*)&h, sizeof(IMAGE_FILE_HEADER));

    return h;
}

template <>
IMAGE_OPTIONAL_HEADER64 PEFile::readHeader<IMAGE_OPTIONAL_HEADER64>(std::istream& fp)
{
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    IMAGE_OPTIONAL_HEADER64 h;

    fp.read((char*)&h, sizeof(h));

    return h;
}

template <>
IMAGE_OPTIONAL_HEADER32 PEFile::readHeader<IMAGE_OPTIONAL_HEADER32>(std::istream& fp)
{
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    IMAGE_OPTIONAL_HEADER32 h;

    fp.read((char*)&h, sizeof(h));

    return h;
}

std::unique_ptr<IMAGE_SECTION_HEADER[]> PEFile::sectionTable(std::istream& fp)
{
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    auto size = file_h.SizeOfOptionalHeader;

    fp.seekg(size, std::ios::cur);

    // IMAGE_SECTION_HEADER* h = (IMAGE_SECTION_HEADER*)malloc(file_h.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    std::unique_ptr<IMAGE_SECTION_HEADER[]> h { new IMAGE_SECTION_HEADER[file_h.NumberOfSections] {} };
    fp.read((char*)h.get(), file_h.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    return h;
}

uint64_t PEFile::sizeofHeaders(std::istream& fp)
{
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    DWORD size = 0;
    if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER64>(fp);
        size = h.SizeOfHeaders;
    } else if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER32>(fp);
        size = h.SizeOfHeaders;
    } else {
        return {};
    }

    return size;
}

uint64_t PEFile::sizeofImage(std::istream& fp)
{
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    DWORD size = 0;
    if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER64>(fp);
        size = h.SizeOfImage;
    } else if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER32>(fp);
        size = h.SizeOfImage;
    } else {
        return {};
    }

    return size;
}

std::vector<uint8_t> PEFile::fileToImage(std::istream& fp)
{
    auto size = 0;
    auto file_h = readHeader<IMAGE_FILE_HEADER>(fp);
    auto numberOfSections = file_h.NumberOfSections;
    auto fileAlignment = 0;
    auto sectionAlignment = 0;
    if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER64>(fp);
        fileAlignment = h.FileAlignment;
        sectionAlignment = h.SectionAlignment;
        size = h.SizeOfHeaders;
    } else if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER32>(fp);
        fileAlignment = h.FileAlignment;
        sectionAlignment = h.SectionAlignment;
        size = h.SizeOfHeaders;
    } else {
        return {};
    }

    auto image_size = sizeofImage(fp);

    fp.seekg(0, std::ios::end);

    fp.seekg(0);

    std::vector<uint8_t> image(image_size);
    const char(&str)[659456] = (const char(&)[659456]) * image.data();
    fp.read((char*)image.data(), size);

    auto sections = sectionTable(fp);

    for (auto i = 0; i < file_h.NumberOfSections; i++) {
        auto section = sections[i];
        auto offset = section.PointerToRawData;
        auto virtualAdderss = section.VirtualAddress;
        auto size = section.SizeOfRawData;

        fp.seekg(offset, std::ios::beg);
        fp.read((char*)image.data() + virtualAdderss, size);
    }
    return image;
}

void PEFile::imageToFile(const std::vector<uint8_t>& data, std::vector<uint8_t>& file_buffer, uint64_t file_size)
{

    auto s_fp = std::stringstream(std::string(data.begin(), data.end()));

    auto size = 0;
    auto file_h = readHeader<IMAGE_FILE_HEADER>(s_fp);
    auto numberOfSections = file_h.NumberOfSections;
    auto fileAlignment = 0;
    auto sectionAlignment = 0;
    auto image_size = 0;
    if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER64>(s_fp);
        fileAlignment = h.FileAlignment;
        sectionAlignment = h.SectionAlignment;
        size = h.SizeOfHeaders;
        image_size = h.SizeOfImage;
    } else if (file_h.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32)) {
        auto h = readHeader<IMAGE_OPTIONAL_HEADER32>(s_fp);
        fileAlignment = h.FileAlignment;
        sectionAlignment = h.SectionAlignment;
        size = h.SizeOfHeaders;
    } else {
        return;
    }

    memcpy(file_buffer.data(), data.data(), size);

    auto sections = sectionTable(s_fp);

    for (auto i = 0; i < file_h.NumberOfSections; i++) {
        auto section = sections[i];
        auto offset = section.PointerToRawData;
        auto virtualAdderss = section.VirtualAddress;
        auto size = section.SizeOfRawData;

        memcpy(file_buffer.data() + offset, data.data() + virtualAdderss, size);
    }
}