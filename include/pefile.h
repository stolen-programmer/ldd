#pragma once

//
// Created by 20264 on 2024/7/1.
//

#ifndef LDD_PE_FILE_H
#define LDD_PE_FILE_H

// 三方库

// 标准库
#include <fstream>

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
};

#endif // LDD_PE_FILE_H
