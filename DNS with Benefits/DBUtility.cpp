//
//  DBUtility.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/19/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBUtility.hpp"

#include <iomanip>
#include <mutex>

std::mutex hex_dump_mtx;

// Useful func
void hex_dump_data(size_t length, const uint8_t *data, std::ostream &o, int char_per_line)
{
    std::unique_lock<std::mutex> lock(hex_dump_mtx);
    o << "Data: Length -> " << length << "\n";
    o << "----------------\n";
    o << std::right << std::setfill('0') << std::hex;
    
    for (size_t i = 0; i < length;)
    {
        int j = 0;
        o << std::setw(8) << i << ": ";
        for (; i+j < length-1 && j < char_per_line-1; j+=2)
            o << std::setw(2) << (uint16_t)data[i+j] << std::setw(2) << (uint16_t)data[i+j+1] << " ";
        if (j == char_per_line-1 && i+j <= length-1)
            o << std::setw(2) << (uint16_t)data[(++j) + i] << "00" << " ";
        for (; j < char_per_line-1; j+=2)
            o << "     ";
        if (j == char_per_line-1)
            o << "     ";
        
        o << "  ";
        for (j = 0; i+j < length && j < char_per_line; j++)
            o << (std::isprint(data[i+j]) ? (char)data[i+j] : '.');
        o << "\n";
        i += j;
    }
    o << "----------------\n\n" << std::dec;
}

uint32_t adler32(const void *buf, size_t buflength) {
    const uint8_t *buffer = (const uint8_t*)buf;
    
    uint32_t s1 = 1;
    uint32_t s2 = 0;
    
    for (size_t n = 0; n < buflength; n++) {
        s1 = (s1 + buffer[n]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) | s1;
}
