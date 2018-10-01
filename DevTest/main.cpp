//
//  main.cpp
//  DevTest
//
//  Created by Soroush Faghihi on 5/29/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include <iostream>
#include <thread>

#include "DBCircularBuffer.hpp"
#include "DBRadixTrie.hpp"
#include "DBDNSServer.hpp"

std::atomic<unsigned long> hoh(0);
const unsigned long n = 4000000;
const int tn = 8;

DBCircularBuffer<unsigned long, 320> buffy("bufbuf");


void f2(unsigned long i)
{
    for (unsigned long j = i; j <= n; j += tn) {
        unsigned long buf = buffy.dequeue();
        //std::cout << "\n----- " << i;
        hoh += buf;
    }
}

void f1(unsigned long i)
{
    for (unsigned long j = i; j <= n; j += tn) {
        //std::cout << "\n+++++ " << i;
        buffy.enqueue(j);
    }
}

int main(int argc, const char * argv[])
{
    // insert code here...
    /*const int R = 4;
    DBRadixString<R> str("www.aaaaa-apple.com");
    DBRadixString<R> tst("netflix.nen");
    DBRadixString<R> tst2("baaaa-apple.com");
    DBRadixString<R> tst3(tst);
    DBRadixString<R> tst4(tst2, 3);
    
    std::cout
        << "Testing DBRadixString...\n" << "Ref: " << str << "\n"
        << "Test1: " << tst << " -> " << str.compare(0, tst, 0) << "\n"
        << "Test2: " << tst2 << " -> " << str.compare(0, tst2, 0) << "\n"
        << "Test3: " << tst3 << " -> " << str.compare(0, tst3, 0) << "\n"
        << "Test4: " << tst4 << " -> " << str.compare(3, tst4, 0) << "\n";
    
    
    // Radix Trie test
    std::cout
        << "\n--------------------------------\n\n"
        << "Testing Trie!!!!\n\n";
    
    DBRadixTrie<R, int>hah;
    hah.insert("apple.com", 1);
    hah.insert("*kaple.com", 10);
    hah.insert("netflix.net", 0);
    hah.insert("*.b.apple.com", 2);
    hah.insert("www.b.apple.com", 3);
    
    const char *rad_tst1 = "bapple.com";
    std::cout
        << "\n--------------------------------\n"
        << "Looking up key: " << rad_tst1 << "\n";
    for (auto v : *hah.lookup(rad_tst1)) {
        std::cout << "\t" << v << "\n";
    }
    
    const char *rad_tst2 = "apple.com";
    std::cout
        << "\n--------------------------------\n"
        << "Looking up key: " << rad_tst2 << "\n";
    for (auto v : *hah.lookup(rad_tst2)) {
        std::cout << "\t" << v << "\n";
    }
    
    const char *rad_tst3 = "www.b.apple.com";
    std::cout
    << "\n--------------------------------\n"
    << "Looking up key: " << rad_tst3 << "\n";
    for (auto v : *hah.lookup(rad_tst3)) {
        std::cout << "\t" << v << "\n";
    }
    
    const char *rad_tst4 = "www.netflix.net";
    std::cout
    << "\n--------------------------------\n"
    << "Looking up key: " << rad_tst4 << "\n";
    for (auto v : *hah.lookup(rad_tst4)) {
        std::cout << "\t" << v << "\n";
    }
    
    const char *rad_tst5 = "sdssdkaple.com";
    std::cout
    << "\n--------------------------------\n"
    << "Looking up key: " << rad_tst5 << "\n";
    for (auto v : *hah.lookup(rad_tst5)) {
        std::cout << "\t" << v << "\n";
    }*/
    
    std::vector<pthread_t> ts;
    for (long i = 0; i < 2*tn; i++) {
        pthread_t t;
        if (i % 2) {
            pthread_create(&t, NULL, (void *(*)(void *))&f2, (void *)(i/2));
        } else {
            //std::cout << i/2 << " + ";
            pthread_create(&t, NULL, (void *(*)(void *))&f1, (void *)(i/2));
        }
        ts.push_back(t);
    }
    std::cout << "DONE Creating\n";
    for (auto t : ts) {
        pthread_join(t, NULL);
    }
    
    std::cout << "\nValue of hoh: " << hoh << ", should be " << (n + 1) * n / 2 << ".\n";
    return 0;
}
