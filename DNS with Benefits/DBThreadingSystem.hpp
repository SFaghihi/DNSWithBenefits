//
//  DBThreadingSystem.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 6/24/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBThreadingSystem_hpp
#define DBThreadingSystem_hpp

/*  Old Stuff
#include <stdio.h>
#include <vector>
#include <pthread.h>

//#include "common.h"

template <class T>
class DBThread {
public:
    typedef void (T::*ThreadMemFncT) (DBThread<T> &);
    
private:
    ThreadMemFncT mem_func;
    T *object;
    pthread_t thread_id;
    
    static void *pthread_wrapper (void *self_void)
    {
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        DBThread<T> *self = static_cast<DBThread<T> *>(self_void);
        std::invoke(self->mem_func, self->object, *self);
        return NULL;
    }
    
public:
    DBThread<T>(T *obj_ptr, ThreadMemFncT mem_func)
    : object(obj_ptr), mem_func(mem_func)
    {
        pthread_create(&thread_id, NULL, &pthread_wrapper, (void *)this);
    }
    
    void test_cancellation()
    {
        pthread_testcancel();
    }
    
    void cancel()
    {
        pthread_cancel(thread_id);
    }
    
    void *join()
    {
        void *thread_return;
        pthread_join(thread_id, &thread_return);
        return thread_return;
    }
};

template <class T>
class DBThreadPool {
private:
    std::vector<DBThread<T> > threads;
    T *object;
    
public:
    DBThreadPool<T> (T *obj_ptr, size_t pool_count, typename DBThread<T>::ThreadMemFncT mem_func)
    : object(obj_ptr)
    {
        // Setup the pool
        threads.reserve(pool_count);
        for (size_t i = 0; i < pool_count; i++)
            threads.push_back(DBThread<T>(obj_ptr, mem_func));
    }
    
    void stop_threads()
    {
        for (DBThread<T> thread: threads)
            thread.cancel();
        
        for (DBThread<T> thread: threads)
            thread.join();
    }
};*/


// Better Version!!!

#include <iostream>
#include <vector>
#include <functional>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <Block.h>

#include "DBCommon.hpp"
#include "Exception.hpp"

//#include "common.h"

template <class T, typename ...Args>
class DBThread {
public:
    
    //typedef void (T::*ThreadMemFncT) (DBThread<T> &);
    using SelfType = DBThread<T, Args...>;
    using ThreadMemFncT = std::function<void (T&, SelfType &, Args...)>;
    
private:
    //std::atomic_flag should_continue = ATOMIC_FLAG_INIT;
    std::atomic<bool> should_continue;
    ThreadMemFncT mem_func;
    std::tuple<T&, SelfType &, Args...> func_args;
    //pthread_t thread_id;
    dispatch_queue_t queue;
    dispatch_group_t group;
    dispatch_block_t block;
    
    static void *pthread_wrapper (void *self_void)
    {
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        SelfType *self = static_cast<SelfType *>(self_void);
        //((self->object).*(self->mem_func))(*self);
        std::apply(self->mem_func, self->func_args);
        return NULL;
    }
    
public:
    DBThread<T, Args...>(T &obj_ptr, ThreadMemFncT mem_func, dispatch_queue_t queue, dispatch_group_t group, Args... args)
    : mem_func(mem_func), func_args(obj_ptr, *this), group(group), queue(queue)
    {
        //printf("\nMem_fnc: 0x%lx\n", this->mem_func);
        dispatch_retain(queue);
        dispatch_retain(group);
        block = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
            std::apply(this->mem_func, this->func_args);
        });
    }
    
    DBThread<T, Args...>(T &obj_ptr, ThreadMemFncT mem_func, Args... args)
    : mem_func(mem_func), func_args(obj_ptr, *this),
    group(dispatch_group_create()), queue(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0))
    {
        //printf("\nMem_fnc: 0x%lx\n", this->mem_func);
        dispatch_retain(queue);
        dispatch_retain(group);
        block = block = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
            std::apply(this->mem_func, this->func_args);
        });
    }
    
    ~DBThread<T, Args...>()
    {
        cancel();
        join();
        Block_release(block);
    }
    
    bool try_test_cancellation()
    {
        return !should_continue;//.test_and_set();
    }
    
    //void test_cancellation()
    //{
    //    pthread_testcancel();
    //}
    
    void start()
    {
        should_continue = true;//.test_and_set();
        dispatch_group_async(group, queue, block);
        dispatch_release(queue);
        dispatch_release(group);
        //pthread_create(&thread_id, NULL, &pthread_wrapper, (void *)this);
    }
    
    void cancel()
    {
        should_continue = false;//.clear();
        //pthread_cancel(thread_id);
    }
    
    bool join()
    {
        //void *thread_return;
        //pthread_join(thread_id, &thread_return);
        return !dispatch_block_wait(block, dispatch_time(DISPATCH_TIME_NOW, 30e9));
    }
};

template <class T>
class DBThread<T> {
public:
    
    //typedef void (T::*ThreadMemFncT) (DBThread<T> &);
    using ThreadMemFncT = std::function<void (T&, DBThread<T> &)>;
    using SelfType = DBThread<T>;
    
private:
    //std::atomic_flag should_continue;
    std::atomic<bool> should_continue;
    ThreadMemFncT mem_func;
    std::tuple<T&, SelfType &> func_args;
    //pthread_t thread_id;
    dispatch_queue_t queue;
    dispatch_group_t group;
    dispatch_block_t block;
    
    static void *pthread_wrapper (void *self_void)
    {
        //pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        //pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        SelfType *self = static_cast<SelfType *>(self_void);
        //((self->object).*(self->mem_func))(*self);
        std::apply(self->mem_func, self->func_args);
        return NULL;
    }
    
public:
    DBThread<T>(T &obj_ptr, ThreadMemFncT mem_func, dispatch_queue_t queue, dispatch_group_t group)
    : mem_func(mem_func), func_args(obj_ptr, *this), group(group), queue(queue)
    {
        //printf("\nMem_fnc: 0x%lx\n", this->mem_func);
        dispatch_retain(queue);
        dispatch_retain(group);
        block = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
            std::apply(this->mem_func, this->func_args);
        });
    }
    
    DBThread<T>(T &obj_ptr, ThreadMemFncT mem_func)
    : mem_func(mem_func), func_args(obj_ptr, *this),
      group(dispatch_group_create()), queue(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0))
    {
        //printf("\nMem_fnc: 0x%lx\n", this->mem_func);
        dispatch_retain(queue);
        dispatch_retain(group);
        block = dispatch_block_create(DISPATCH_BLOCK_INHERIT_QOS_CLASS, ^{
            std::apply(this->mem_func, this->func_args);
        });
    }
    
    ~DBThread<T>()
    {
        cancel();
        join();
        Block_release(block);
    }
    
    bool try_test_cancellation()
    {
        return !should_continue;//.test_and_set();
    }
    
    //void test_cancellation()
    //{
    //    pthread_testcancel();
    //}
    
    void start()
    {
        should_continue = true;//.test_and_set();
        dispatch_group_async(group, queue, block);
        dispatch_release(queue);
        dispatch_release(group);
        //pthread_create(&thread_id, NULL, &pthread_wrapper, (void *)this);
    }
    
    void cancel()
    {
        should_continue = false;//.clear();
        //pthread_cancel(thread_id);
    }
    
    bool join()
    {
        //void *thread_return;
        //pthread_join(thread_id, &thread_return);
        return !dispatch_block_wait(block, dispatch_time(DISPATCH_TIME_NOW, 30e9));
    }
};


template <class T, typename ...Args>
class DBThreadPool {
public:
    using ThreadMemFncT = std::function<void (T&, DBThread<T, Args...> &, Args...)>;
    using DBThreadType = DBThread<T, Args...>;
    using SelfType = DBThreadPool<T, Args...>;
    
private:
    size_t pool_count;
    std::vector<std::unique_ptr<DBThreadType> > threads;
    ThreadMemFncT mem_func;
    dispatch_queue_t pool_queue;
    dispatch_group_t pool_group;
    
public:
    DBThreadPool<T, Args...> (T&object, size_t pool_count, ThreadMemFncT mem_func, const char *pool_name, Args... args)
    : pool_count(pool_count), mem_func(mem_func),
      pool_queue(dispatch_queue_create(pool_name, DISPATCH_QUEUE_CONCURRENT)), pool_group(dispatch_group_create())
    {
        // Check for a failure of dispatch group creation. (It can happen!!!)
        if (!pool_group) {
            throw Exception("Couldn't create dispatch group.");
        }
        
        // Setup the pool
        threads.reserve(pool_count);
        for (size_t i = 0; i < pool_count; i++)
            threads.push_back(DBThreadType(object, mem_func, pool_queue, pool_group, &args...));
    }
    
    DBThreadPool<T, Args...> (T&object, size_t pool_count, ThreadMemFncT mem_func, Args... args)
    : pool_count(pool_count), mem_func(mem_func),
    pool_queue(dispatch_queue_create("", DISPATCH_QUEUE_CONCURRENT)), pool_group(dispatch_group_create())
    {
        // Check for a failure of dispatch group creation. (It can happen!!!)
        if (!pool_group) {
            throw Exception("Couldn't create dispatch group.");
        }
        
        // Setup the pool
        threads.reserve(pool_count);
        for (size_t i = 0; i < pool_count; i++)
            threads.push_back(std::unique_ptr<DBThreadType>(new DBThreadType(object, mem_func, pool_queue, pool_group, &args...)));
    }
    
    ~DBThreadPool<T, Args...>()
    {
        stop_threads();
    }
    
    void start_threads()
    {
        //printf("Obj: %lx, mem_fnc: %lx\n", &object, mem_func);
        // Start the threads
        for (auto &thread_ptr : threads) {
            thread_ptr->start();
        }
    }
    
    void stop_threads()
    {
        dispatch_release(pool_queue);
        
        for (auto &thread_ptr: threads)
            thread_ptr->cancel();
        
        if (dispatch_group_wait(pool_group, dispatch_time(DISPATCH_TIME_NOW, 30e9)))
            throw Exception("Couldn't finish the threads within timeout!", 0);
        
        dispatch_release(pool_group);
        
        //for (DBThreadType &thread: threads)
        //    thread.join();
    }
};

template <class T>
class DBThreadPool<T> {
public:
    using ThreadMemFncT = std::function<void (T&, DBThread<T> &)>;
    using DBThreadType = DBThread<T>;
    using SelfType = DBThreadPool<T>;
    
private:
    size_t pool_count;
    std::vector<std::unique_ptr<DBThreadType> > threads;
    ThreadMemFncT mem_func;
    dispatch_queue_t pool_queue;
    dispatch_group_t pool_group;
    
    
public:
    DBThreadPool<T> (T &object, size_t pool_count, ThreadMemFncT mem_func, const char *pool_name = "")
    : pool_count(pool_count), mem_func(mem_func),
      pool_queue(dispatch_queue_create(pool_name, DISPATCH_QUEUE_CONCURRENT)), pool_group(dispatch_group_create())
    {
        // Check for a failure of dispatch group creation. (It can happen!!!)
        if (!pool_group) {
            throw Exception("Couldn't create dispatch group.");
        }
        
        // Setup the pool
        threads.reserve(pool_count);
        for (size_t i = 0; i < pool_count; i++)
            threads.push_back(std::unique_ptr<DBThreadType>(new DBThreadType(object, mem_func, pool_queue, pool_group)));
    }
    
    ~DBThreadPool<T>()
    {
        stop_threads();
    }
    
    void start_threads()
    {
        //printf("Obj: %lx, mem_fnc: %lx\n", &object, mem_func);
        // Start the threads
        for (auto &thread_ptr : threads) {
            thread_ptr->start();
        }
    }
    
    void stop_threads()
    {
        dispatch_release(pool_queue);
        
        for (auto &thread_ptr: threads)
            thread_ptr->cancel();
        
        if (dispatch_group_wait(pool_group, dispatch_time(DISPATCH_TIME_NOW, 30e9)))
            throw Exception("Couldn't finish the threads within timeout!", 0);
        
        dispatch_release(pool_group);
        //for (DBThreadType &thread: threads)
        //    thread.join();
    }
};


#endif /* DBThreadingSystem_hpp */
