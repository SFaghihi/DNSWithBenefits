//
//  DBMatchSystem.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBMatchSystem_hpp
#define DBMatchSystem_hpp

#include <pthread.h>
#include <semaphore.h>

#include "DBRadixTrie.hpp"

/*
 * The Multithreaded version of DBRadixTree.
 * Model:
 *      init -> read -> c
 */
template <int R, class V>
class DBMatchSystem
{
public:
    typedef void (*match_system_init_fnc_t) (DBRadixTrie<R, std::vector<V>> &, void *);
    
private:
    DBRadixTrie<R, std::vector<V>> radix_trie;
    mutable pthread_rwlock_t rw_lock;
    sem_t *reinit_sem;
    char *sem_name;
    const char *sem_template = "/sem.DBMatch.XXXXXXXX";
    pthread_t reinit_thread;
    match_system_init_fnc_t reinit_fnc;
    void *init_fnc_arg;
    
    static void *reinit_routine(void *self_void);
    
public:
    
    DBMatchSystem<R, V> (match_system_init_fnc_t init_fnc, void *init_fnc_arg);
    ~DBMatchSystem<R, V> ();
    
    /*
     * This method is safe to use inside signal handlers!
     *
     * This is intentionaly implemented that way to provide for graceful
     * reset of filtering without restarting the server.
     */
    void signal_reinit();
    
    void insert(const std::string &key, V value);
    std::vector<V> lookup(const std::string &key) const;
};

#endif /* DBMatchSystem_hpp */
