#pragma once

#ifndef LDD_PE_FILE_H
#define LDD_PE_FILE_H

//
// Created by 20264 on 2024/7/1.
//

#include <cstdint>
#include <istream>
#include <memory>
#include <winnt.h>

// 三方库

// 标准库
#include <fstream>
#include <vector>

// 系统头
#include <Windows.h>

// 项目头

struct PEFile {

    template <typename T>
    static T readHeader(std::istream& fp)
    {

        T h = { 0 };
        fp.seekg(0);
        fp.read((char*)&h, sizeof(T));

        return h;
    }

    static DWORD readPEMarker(std::istream& fp);

    template <>
    static IMAGE_FILE_HEADER readHeader(std::istream& fp);

    template <>
    static IMAGE_OPTIONAL_HEADER64 readHeader(std::istream& fp);

    template <>
    static IMAGE_OPTIONAL_HEADER32 readHeader(std::istream& fp);

    static std::unique_ptr<IMAGE_SECTION_HEADER[]> sectionTable(std::istream& fp);

    static uint64_t sizeofHeaders(std::istream& fp);

    static uint64_t sizeofImage(std::istream& fp);

    static std::vector<uint8_t> fileToImage(std::istream& fp);
    static void imageToFile(const std::vector<uint8_t>& data, std::vector<uint8_t>& file_buffer, uint64_t file_size);
};

#endif // LDD_PE_FILE_H
