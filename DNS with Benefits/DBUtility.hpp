//
//  DBUtility.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/14/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBUtility_h
#define DBUtility_h

#include <iostream>
#include <type_traits>

#include <net/route.h>

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// trim from start (copying)
static inline std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// trim from end (copying)
static inline std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}

// trim from both ends (copying)
static inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

// Array delete
template<class _Tp>
struct array_deleter
{
    static_assert(!std::is_function<_Tp>::value,
                  "default_delete cannot be instantiated for function types");
    
    _LIBCPP_INLINE_VISIBILITY constexpr array_deleter() noexcept = default;
    
    template <class _Up>
    //_LIBCPP_INLINE_VISIBILITY
    array_deleter(const array_deleter<_Up>&,
                  typename std::enable_if<std::is_convertible<_Up*, _Tp*>::value>::type* =
                  0) _NOEXCEPT {}
    
    _LIBCPP_INLINE_VISIBILITY void operator()(_Tp* __ptr) const _NOEXCEPT {
        static_assert(sizeof(_Tp) > 0,
                      "default_delete can not delete incomplete type");
        static_assert(!std::is_void<_Tp>::value,
                      "default_delete can not delete incomplete type");
        
        delete[] __ptr;
    }
};

// new[] unique and shared pointer
//template<typename Tp> using array_shared_ptr = std::shared_ptr<Tp, array_deleter<Tp> >;
template<typename Tp> using array_unique_ptr = std::unique_ptr<Tp, array_deleter<Tp> >;


// Operator deleter
template<class _Tp>
struct operator_deleter
{
    static_assert(!std::is_function<_Tp>::value,
                  "default_delete cannot be instantiated for function types");
    
    _LIBCPP_INLINE_VISIBILITY constexpr operator_deleter() noexcept = default;
    
    template <class _Up>
    _LIBCPP_INLINE_VISIBILITY
    operator_deleter(const operator_deleter<_Up>&,
                     typename std::enable_if<std::is_convertible<_Up*, _Tp*>::value>::type* =
                     0) _NOEXCEPT {}
    
    _LIBCPP_INLINE_VISIBILITY void operator()(_Tp* __ptr) const _NOEXCEPT {
        static_assert(sizeof(_Tp) > 0,
                      "default_delete can not delete incomplete type");
        static_assert(!std::is_void<_Tp>::value,
                      "default_delete can not delete incomplete type");
        
        ::operator delete(static_cast<void *>(__ptr));
    }
};

// Operator new unique pointer
template<typename Tp> using op_unique_ptr = std::unique_ptr<Tp, operator_deleter<Tp> >;

// Malloc deleter
template<class _Tp>
struct malloc_deleter
{
    static_assert(!std::is_function<_Tp>::value,
                  "default_delete cannot be instantiated for function types");
    
    _LIBCPP_INLINE_VISIBILITY constexpr malloc_deleter() noexcept = default;
    
    template <class _Up>
    _LIBCPP_INLINE_VISIBILITY
    malloc_deleter(const malloc_deleter<_Up>&,
                     typename std::enable_if<std::is_convertible<_Up*, _Tp*>::value>::type* =
                     0) _NOEXCEPT {}
    
    _LIBCPP_INLINE_VISIBILITY void operator()(_Tp* __ptr) const _NOEXCEPT {
        static_assert(sizeof(_Tp) > 0,
                      "default_delete can not delete incomplete type");
        static_assert(!std::is_void<_Tp>::value,
                      "default_delete can not delete incomplete type");
        
        free(static_cast<void *>(__ptr));
    }
};

// Operator new unique pointer
template<typename Tp> using malloc_unique_ptr = std::unique_ptr<Tp, malloc_deleter<Tp> >;

using unique_sockaddr = malloc_unique_ptr<sockaddr>;

// Useful func
void hex_dump_data(size_t length, const uint8_t *data, std::ostream &o = std::cout, int char_per_line = 8);

uint32_t adler32(const void *buf, size_t buflength);

// Awesome std::cout
static const std::ostream &g_cout = std::cout;

#endif /* DBUtility_h */
