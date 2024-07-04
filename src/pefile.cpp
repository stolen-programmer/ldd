//
// Created by 20264 on 2024/7/1.
//

// 标准头
#include <utility>

// 系统头
#include <Windows.h>
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

