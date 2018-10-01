//
//  DBFilteringSystem.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 6/24/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBFilteringSystem_hpp
#define DBFilteringSystem_hpp

#include "DBCommon.hpp"
#include "DBMatchSystem.hpp"
#include "DBFilteringController.hpp"
#include "DBThreadingSystem.hpp"

class DBPreFilteringSystem
{
private:
    DBFilterLocation location;
    DBFilteringController *controller;
    DBDNSMatchSystemPre matching_system;
    
    // Threading Stuff
    translated_buffer_t  *prefiltering_queue;
    prefiltered_buffer_t *resolving_queue;
    resolved_buffer_t    *postfiltering_queue;
    DBThreadPool<DBPreFilteringSystem> thread_pool;
    
    
    static void default_initializer(DBDNSTriePre &trie, void *self_void);
    void filter_loop(DBThread<DBPreFilteringSystem> &thread);
    
public:
    DBPreFilteringSystem(DBFilteringController *controller, size_t _thread_pool_count,
                         translated_buffer_t *_prefiltering_queue,
                         prefiltered_buffer_t *resolving_queue, resolved_buffer_t *postfiltering_queue);
    ~DBPreFilteringSystem();
    
    void start_threads();
    void stop_threads();
    void signal_reinit();
};

class DBPostFilteringSystem
{
private:
    DBFilterLocation location;
    DBFilteringController *controller;
    DBDNSMatchSystemPost matching_system;
    
    // Threading Stuff
    resolved_buffer_t *postfiltering_queue;
    postfiltered_buffer_t *sending_queue;
    DBThreadPool<DBPostFilteringSystem> thread_pool;
    
    
    static void default_initializer(DBDNSTriePost &trie, void *self_void);
    void filter_loop(DBThread<DBPostFilteringSystem> &thread);
    
public:
    DBPostFilteringSystem(DBFilteringController *controller, size_t _thread_pool_count, resolved_buffer_t *postfiltering_queue,
                          postfiltered_buffer_t *sending_queue);
    ~DBPostFilteringSystem();
    
    void start_threads();
    void stop_threads();
    void signal_reinit();
};

#endif /* DBFilteringSystem_hpp */
