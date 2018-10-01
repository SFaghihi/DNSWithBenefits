//
//  DBCircularBuffer.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 6/2/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBCircularBuffer_hpp
#define DBCircularBuffer_hpp

// Better version

#include "Exception.hpp"

#include <unistd.h>

#include <iostream>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <optional>

template <class V, size_t size>
class DBCircularBuffer {
    std::unique_ptr<V[]> buffer;
    size_t dequeue_idx, enqueue_idx;
    std::mutex queue_mtx;
    size_t length;
    std::condition_variable is_not_empty;
    std::condition_variable is_not_full;
    bool is_dead = false;
    const bool has_pipe_notify = false;
    int rd_pipe, wr_pipe;
    
public:
    DBCircularBuffer<V> (bool _has_pipe_notify = false)
    : buffer(new V[size]), dequeue_idx(0), enqueue_idx(0), length(0), has_pipe_notify(_has_pipe_notify)
    {
        // Get pipes if asked
        if (has_pipe_notify)
        {
            int ps[2];
            if (pipe(ps))
                throw Exception("Pipe creation for DBCircularBuffer");
            rd_pipe = ps[0]; wr_pipe = ps[1];
        }
        // Debugging -> Initialize the buffer elements
        for (int i = 0; i < size; i++)
            buffer[i] = V();
    }
    
    ~DBCircularBuffer<V, size> ()
    {
        is_dead = true;
        is_not_full.notify_all();
        is_not_empty.notify_all();
        {
            std::scoped_lock lck{queue_mtx};
        }
        if (has_pipe_notify)
        {
            close(rd_pipe);
            close(wr_pipe);
        }
    }
    
    int dequeue_fd() const { return rd_pipe; }
    int enqueue_fd() const { return wr_pipe; }
    
    void clear()
    {
        is_dead = true;
        is_not_full.notify_all();
        is_not_empty.notify_all();
        {
            std::scoped_lock lck{queue_mtx};
            buffer.reset(new V[size]);
            dequeue_idx = 0; enqueue_idx = 0; length = 0;
            is_dead = false;
        }
        if (has_pipe_notify)
        {
            close(rd_pipe);
            close(wr_pipe);
        }
    }
    
    bool enqueue(const V &value)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        is_not_full.wait(lock, [this] { return is_dead || length < size; });
        if (is_dead) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = value;
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    bool enqueue(V &&value)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        is_not_full.wait(lock, [this] { return is_dead || length < size; });
        if (is_dead) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = std::move(value);
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    bool try_enqueue(const V &value)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (is_dead || length >= size) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = value;
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    bool try_enqueue(V &&value)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (is_dead || length >= size) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = std::move(value);
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    template <class _Clock, class _Duration>
    bool enqueue_until(const V &value, const std::chrono::time_point<_Clock, _Duration>& t_point)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (!is_not_full.wait_until(lock, t_point, [this] { return is_dead || length < size; }))
            return false;
        
        if (is_dead) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = value;
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    template <class _Clock, class _Duration>
    bool enqueue_until(V &&value, const std::chrono::time_point<_Clock, _Duration>& t_point)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (!is_not_full.wait_until(lock, t_point, [this] { return is_dead || length < size; }))
            return false;
        
        if (is_dead) {
            lock.unlock();
            return false;
        }
        
        if (has_pipe_notify)
            write(wr_pipe, "0", 1);
        
        buffer[enqueue_idx] = std::move(value);
        enqueue_idx = (enqueue_idx + 1) % size;
        length++;
        
        is_not_empty.notify_one();
        lock.unlock();
        
        return true;
    }
    
    std::optional<V> try_dequeue()
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (is_dead || length == 0) {
            lock.unlock();
            return {};
        }
        
        char rd_c;
        if (has_pipe_notify)
            read(rd_pipe, &rd_c, 1);
        
        V return_value = std::move(buffer[dequeue_idx]);
        dequeue_idx = (dequeue_idx + 1) % size;
        length--;
        
        is_not_full.notify_one();
        lock.unlock();
        
        return std::move(return_value);
    }
    
    std::optional<V> dequeue()
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        is_not_empty.wait(lock, [this] { return is_dead || length > 0; });
        if (is_dead) {
            lock.unlock();
            return {};
        }
        
        char rd_c;
        if (has_pipe_notify)
            read(rd_pipe, &rd_c, 1);
        
        V return_value = std::move(buffer[dequeue_idx]);
        dequeue_idx = (dequeue_idx + 1) % size;
        length--;
        
        is_not_full.notify_one();
        lock.unlock();
        
        return std::move(return_value);
    }
    
    template <class _Clock, class _Duration>
    std::optional<V> dequeue_until(const std::chrono::time_point<_Clock, _Duration>& t_point)
    {
        std::unique_lock<std::mutex> lock(queue_mtx);
        if (!is_not_empty.wait_until(lock, t_point, [this] { return is_dead || length > 0; }))
            return {};
        
        if (is_dead) {
            lock.unlock();
            return {};
        }
        
        char rd_c;
        if (has_pipe_notify)
            read(rd_pipe, &rd_c, 1);
        
        V return_value = std::move(buffer[dequeue_idx]);
        dequeue_idx = (dequeue_idx + 1) % size;
        length--;
        
        is_not_full.notify_one();
        lock.unlock();
        
        return std::move(return_value);
    }
    
    // NOT thread safe!!!
    bool is_empty()
    {
        return length == 0;
    }
};


#endif /* DBCircularBuffer_hpp */
