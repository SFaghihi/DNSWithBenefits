//
//  DBMatchSystem.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/20/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBMatchSystem.hpp"

#include "DBRadixTrieImp.hpp"
#include "Exception.hpp"

#include <iostream>
#include <unistd.h>

/************************** Start of DBMatchSystem *****************************/

// Private
template <int R, class V>
void *DBMatchSystem<R, V>::reinit_routine(void *self_void)
{
    DBMatchSystem<R, V> *self = static_cast<DBMatchSystem<R, V> *>(self_void);
    
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    
    while (true)
    {
        // We can cancel waiting for signal
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        
        // Wait for semaphore signal
        sem_wait(self->reinit_sem);
        
        // Flush out semaphore counts
        while (!sem_trywait(self->reinit_sem)) ;
        
        // Make sure we don't cancel
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        
        // Lock the writers lock
        pthread_rwlock_wrlock(&self->rw_lock);
        
        // Clear out the trie and call the initializer
        self->radix_trie.clear();
        self->reinit_fnc(self->radix_trie, self->init_fnc_arg);
        
        // Print out the trie
        //std::cout << "Trie:\n" << self->radix_trie << "\n";
        
        // Relinquish lock
        pthread_rwlock_unlock(&self->rw_lock);
    }
    
    return NULL;
}

// Constructors
template <int R, class V>
DBMatchSystem<R, V>::DBMatchSystem (match_system_init_fnc_t init_fnc, void *init_fnc_arg)
: reinit_fnc(init_fnc), init_fnc_arg(init_fnc_arg)
{
    // initialize pthread and semaphore resources
    pthread_rwlock_init(&rw_lock, NULL);
    
    sem_name = (char *)malloc(strlen(sem_template) + 1);
    strcpy(sem_name, sem_template);
    mktemp(sem_name);
    
    reinit_sem = sem_open(sem_name, O_EXCL | O_CREAT, 0700, 0);
    
    if (reinit_sem == SEM_FAILED)
        throw Exception("DBMatchSystem: sem_init fail.");
    
    // initialize the trie
    init_fnc(radix_trie, init_fnc_arg);
    
    // Setup thread for checking the reinit semaphore
    pthread_create(&reinit_thread, NULL, &reinit_routine, static_cast<void *>(this));
}

template <int R, class V>
DBMatchSystem<R, V>::~DBMatchSystem ()
{
    // Kill the reinit thread
    pthread_cancel(reinit_thread);
    pthread_join(reinit_thread, NULL);
    
    // Destroy pthread and semaphore resources
    pthread_rwlock_destroy(&rw_lock);
    sem_close(reinit_sem);
    sem_unlink(sem_name);
    free(sem_name);
    
    // Clear out the trie
    radix_trie.clear();
}

// Public
template <int R, class V>
std::vector<V> DBMatchSystem<R, V>::lookup(const std::string &key) const
{
    // Lock the readers lock
    pthread_rwlock_rdlock(&rw_lock);
    
    // lookup key, values pair
    std::vector<V> output;
    auto vec_ptr = radix_trie.lookup(key);
    if (vec_ptr)
        output = *vec_ptr;
    
    // Relinquish lock
    pthread_rwlock_unlock(&rw_lock);
    
    return output;
}

/*
 * This method is safe to use inside signal handlers!
 *
 * This is intentionaly implemented that way to provide for graceful
 * reset of filtering without restarting the server.
 */
template <int R, class V>
void DBMatchSystem<R, V>::signal_reinit()
{
    // post the semaphore if not initializing
    sem_post(reinit_sem);
}

template <int R, class V>
void DBMatchSystem<R, V>::insert(const std::string &key, V value)
{
    // Lock the writers lock
    pthread_rwlock_wrlock(&rw_lock);
    
    // insert key, value pair
    radix_trie[key].push_back(value);
    
    // Relinquish lock
    pthread_rwlock_unlock(&rw_lock);
}
