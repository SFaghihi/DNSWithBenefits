//
//  DBFilteringSystem.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/20/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBFilteringSystem.hpp"

/************************** Start of DBPreFilteringSystem *****************************/

// Private
void DBPreFilteringSystem::default_initializer(DBDNSTriePre &trie, void *self_void)
{
    DBPreFilteringSystem *self = static_cast<DBPreFilteringSystem *>(self_void);
    self->controller->prefilter_initializer(trie);
}

void DBPreFilteringSystem::filter_loop(DBThread<DBPreFilteringSystem> &thread)
{
    while (true)
    {
    PREFILTER_START_LOOP:
        if (thread.try_test_cancellation())
            return;
        
        std::optional<translated_request_t *> translated_req_opt = prefiltering_queue->dequeue();
        if (!translated_req_opt.has_value())
            break;
        translated_request_t * translated_req = *translated_req_opt;
        
    PREFILTER_REFILTER_MESSAGE:
        auto questions = translated_req->request->questions();
        
        for (uint16_t i = 0; i < questions.size(); i++)
        {
        PREFILTER_REFILTER_QUESTION:
            DBDNSQuestionRecord &record = questions[i];
            std::vector<pre_callback_fnc_t>callbacks = matching_system.lookup(record.domain_name());
            
            
            for (pre_callback_fnc_t &callback : callbacks)
            {
                if (!callback.query_type.count(kDNSQType_ANY) && !callback.query_type.count(record.query_type))
                    continue;
                
                switch (callback.function(*(translated_req->request), record, callback.user_data))
                {
                    case DBFilterAccept:
                        break;
                        
                    case DBFilterDropQuestion:
                        translated_req->request->delete_record(record);
                    case DBFilterSkipFilter:
                        goto PREFILTER_SKIP_FILTER;
                        
                    case DBFilterMessageModified:
                        goto PREFILTER_REFILTER_MESSAGE;
                        
                    case DBFilterQuestionModified:
                        goto PREFILTER_REFILTER_QUESTION;
                        
                    case DBFilterSkipResolve:
                        translated_req->request->delete_all_records();
                        if (thread.try_test_cancellation())
                            return;
                        postfiltering_queue->enqueue(new resolved_response_t(translated_req->incoming_addr, translated_req->request));
                        
                    case DBFilterReject:
                    default:
                        delete translated_req;
                        goto PREFILTER_START_LOOP;
                }
            }
            
        PREFILTER_SKIP_FILTER:
            continue;
        }
        
        translated_req->request->delete_all_records();
        
        if (thread.try_test_cancellation())
            return;
        
        resolving_queue->enqueue(new filtered_request_t(translated_req));
    }
}


DBPreFilteringSystem::DBPreFilteringSystem(DBFilteringController *controller, size_t _thread_pool_count,
                                           translated_buffer_t *_prefiltering_queue, prefiltered_buffer_t *resolving_queue,
                                           resolved_buffer_t *postfiltering_queue)
: location(DBFilterLocationPre), controller(controller),
matching_system(&default_initializer, this), prefiltering_queue(_prefiltering_queue),
resolving_queue(resolving_queue), postfiltering_queue(postfiltering_queue),
thread_pool(*this, _thread_pool_count, &DBPreFilteringSystem::filter_loop)
{
    controller->prefilter_match_system = &matching_system;
}

DBPreFilteringSystem::~DBPreFilteringSystem()
{
    controller->prefilter_deconstructed();
}


// Public
void DBPreFilteringSystem::start_threads() { thread_pool.start_threads();     }
void DBPreFilteringSystem::stop_threads()  { thread_pool.stop_threads();      }
void DBPreFilteringSystem::signal_reinit() { matching_system.signal_reinit(); }

/************************** Start of DBPostFilteringSystem *****************************/

// Private
void DBPostFilteringSystem::default_initializer(DBDNSTriePost &trie, void *self_void)
{
    DBPostFilteringSystem *self = static_cast<DBPostFilteringSystem *>(self_void);
    self->controller->postfilter_initializer(trie);
}

void DBPostFilteringSystem::filter_loop(DBThread<DBPostFilteringSystem> &thread)
{
    while (true)
    {
    POSTFILTER_START_LOOP:
        if (thread.try_test_cancellation())
            return;
        
        std::optional<resolved_response_t *> resolved_req_opt = postfiltering_queue->dequeue();
        if (!resolved_req_opt.has_value())
            break;
        resolved_response_t *resolved_req = *resolved_req_opt;
        
    POSTFILTER_REFILTER_MESSAGE:
        auto answers = resolved_req->response->answers();
        
        for (uint16_t i = 0; i < answers.size(); i++)
        {
        POSTFILTER_REFILTER_RECORD:
            DBDNSResourceRecord &record = answers[i];
            std::vector<post_callback_fnc_t>callbacks = matching_system.lookup(record.domain_name());
            if (debug_print_on)
                if (callbacks.size() == 0)
                    std::cout << "Query: " << record.domain_name() << "\n";
            
            for (post_callback_fnc_t &callback : callbacks)
            {
                if (!callback.query_type.count(kDNSQType_ANY) && !callback.query_type.count(record.query_type))
                    continue;
                
                switch (callback.function(*(resolved_req->response), record, callback.user_data))
                {
                    case DBFilterAccept:
                        break;
                        
                    case DBFilterDropRecord:
                        resolved_req->response->delete_record(record);
                    case DBFilterSkipFilter:
                        goto POSTFILTER_SKIP_FILTER;
                        
                    case DBFilterMessageModified:
                        goto POSTFILTER_REFILTER_MESSAGE;
                        
                    case DBFilterRecordModified:
                        goto POSTFILTER_REFILTER_RECORD;
                        
                    case DBFilterReject:
                    default:
                        delete resolved_req;
                        goto POSTFILTER_START_LOOP;
                }
            }
            
        POSTFILTER_SKIP_FILTER:
            continue;
        }
        
        resolved_req->response->delete_all_records();
        
        if (thread.try_test_cancellation())
            return;
        
        sending_queue->enqueue(new filtered_response_t(resolved_req));
    }
}


// Constructor
DBPostFilteringSystem::DBPostFilteringSystem(DBFilteringController *controller, size_t _thread_pool_count,
                                             resolved_buffer_t *postfiltering_queue, postfiltered_buffer_t *sending_queue)
: location(DBFilterLocationPost), controller(controller), matching_system(&default_initializer, this), postfiltering_queue(postfiltering_queue), sending_queue(sending_queue), thread_pool(*this, _thread_pool_count, &DBPostFilteringSystem::filter_loop)
{
    controller->postfilter_match_system = &matching_system;
}

DBPostFilteringSystem::~DBPostFilteringSystem()
{
    controller->postfilter_deconstructed();
}


// Public
void DBPostFilteringSystem::start_threads() { thread_pool.start_threads();     }
void DBPostFilteringSystem::stop_threads()  { thread_pool.stop_threads();      }
void DBPostFilteringSystem::signal_reinit() { matching_system.signal_reinit(); }
