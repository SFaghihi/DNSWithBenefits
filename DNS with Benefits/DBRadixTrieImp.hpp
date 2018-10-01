//
//  DBRadixTrie.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/20/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBRadixTrie.hpp"
#include "Exception.hpp"

#include <list>
#include <xmmintrin.h>

inline uint64_t div_round_up(uint64_t a, uint64_t b) { return (a + b - 1) / b; }
inline uint32_t div_round_up(uint32_t a, uint32_t b) { return (a + b - 1) / b; }
inline uint16_t div_round_up(uint16_t a, uint16_t b) { return (a + b - 1) / b; }
inline uint8_t div_round_up(uint8_t a, uint8_t b) { return (a + b - 1) / b; }

/************************** Start of DBRadixString *****************************/
// R must be able to be aligned with char => R can only be 1, 2, 4, 8
template <uint8_t R>
class DBRadixString
{
    static constexpr uint8_t num_of_el_in_byte = 8 / R;
    uint8_t * const _string;
    
    static inline uint64_t read_uint64_misaligned(const uint8_t *data, uint8_t mis);
    static inline uint64_t read_uint64_aligned(const uint8_t *data, uint8_t mis);
    
    static inline uint8_t read_uint8_misaligned(const uint8_t *data, uint8_t mis);
    static inline uint8_t read_uint8_aligned(const uint8_t *data, uint8_t mis);
    
public:
    size_t _length, _start_offset = 0;
    
    /*
     * Constructors
     */
    DBRadixString<R> (const uint8_t *string, size_t length);
    DBRadixString<R> (const char *string);
    DBRadixString<R> (const std::string string);
    DBRadixString<R> (const DBRadixString<R>& string, size_t start_idx);
    DBRadixString<R> (const DBRadixString<R>& string);
    ~DBRadixString<R> ();
    
    // Return the offset index of end position for the shared string, where shared string is [start_idx, start_idx + diff_idx)
    // Which means a return of 0 indicates no match.
    size_t compare(size_t start_idx, const DBRadixString<R>& other_string, size_t other_start_idx) const;
    size_t compare(size_t start_idx, size_t max_length, const DBRadixString<R>& other_string, size_t other_start_idx) const;
    
    uint8_t first_char() const;
    uint8_t char_at(size_t idx) const;
    
    friend std::ostream& operator<<(std::ostream& os, const DBRadixString& str)
    {
        os << str._string << ", fc: " << (int)str.first_char() << ", len: " << str._length << ", so: " << str._start_offset;
        return os;
    }

};

// Private
template <uint8_t R>
inline uint64_t DBRadixString<R>::read_uint64_misaligned(const uint8_t *data, uint8_t mis)
{
    // Read a 64 bit value in a bit misaligned manner
    return ((*reinterpret_cast<const uint64_t *>(data) << mis) | (*(reinterpret_cast<const uint64_t *>(data)+1) >> (sizeof(uint64_t) - mis)))
    & (uint64_t)-1;
    //return (*(uint64_t *)data << mis) | ((*(uint64_t *)data >> (64 - mis)) & ((1 << mis) - 1));
}

template <uint8_t R>
inline uint64_t DBRadixString<R>::read_uint64_aligned(const uint8_t *data, uint8_t mis)
{
    return *(uint64_t *)data;
}

template <uint8_t R>
inline uint8_t DBRadixString<R>::read_uint8_misaligned(const uint8_t *data, uint8_t mis)
{
    return ((*data << mis) | (*(data+1) >> (8 - mis))) & 0xff;
    //return (*data << mis) | ((*data >> (8 - mis)) & ((1 << mis) - 1));
}

template <uint8_t R>
inline uint8_t DBRadixString<R>::read_uint8_aligned(const uint8_t *data, uint8_t mis)
{
    return *data;
}


// Constructors
template <uint8_t R>
DBRadixString<R>::DBRadixString (const uint8_t *string, size_t length)
: _length(length), _string(new uint8_t [(length * R + 7) / 8 + 1])
{
    // Add one null byte to terminate string properly for debugging.
    size_t i = (length * R + 7) / 8;
    _string[i] = 0;
    for (i--; i != -1 ; i--)
        _string[i] = *(string++);
}

template <uint8_t R>
DBRadixString<R>::DBRadixString (const char *string) : DBRadixString<R>((const uint8_t *)string, strlen((const char *)string) * 8 / R) {}

template <uint8_t R>
DBRadixString<R>::DBRadixString (const std::string string) : DBRadixString<R>((const uint8_t *)string.c_str(), string.length() * 8 / R) {}

template <uint8_t R>
DBRadixString<R>::DBRadixString (const DBRadixString<R>& string, size_t start_idx) : _length(string._length - start_idx), _string(new uint8_t [((string._length - start_idx) * R + 7) / 8 + 1]), _start_offset((start_idx + string._start_offset) % (8 / R))
{
    memcpy(_string, string._string + ((start_idx + string._start_offset) * R) / 8, (_length * R + 7)/8);
    _string[(_length * R + 7) / 8] = 0;
}

template <uint8_t R>
DBRadixString<R>::DBRadixString (const DBRadixString<R>& string) : DBRadixString<R>(string, 0) {}

template <uint8_t R>
DBRadixString<R>::~DBRadixString () { delete[] _string; }


// Public

// Return the offset index of end position for the shared string, where shared string is [start_idx, start_idx + diff_idx)
// Which means a return of 0 indicates no match.
template <uint8_t R>
size_t DBRadixString<R>::compare(size_t start_idx, const DBRadixString<R>& other_string, size_t other_start_idx) const
{
    return compare(start_idx, _length, other_string, other_start_idx);
}

template <uint8_t R>
size_t DBRadixString<R>::compare(size_t start_idx, size_t max_length, const DBRadixString<R>& other_string, size_t other_start_idx) const
{
    /*if (strcmp((const char *)other_string._string, "ten.iamaka.1g.7371a") == 0  && other_string._start_offset == 9)
    {
        std::cout << "Me in HEre!!!\n";
    }*/
    
    // Maximum possible length offset
    size_t max_offset = (other_string._length - other_start_idx) < (max_length - start_idx) ? (other_string._length - other_start_idx) : (max_length - start_idx);
    
    // Correct the start offsets
    start_idx += _start_offset;
    other_start_idx += other_string._start_offset;
    
    // Data pointers
    uint8_t *arr_a = _string;
    uint8_t *arr_b = other_string._string;
    
    // Actual start pointers
    arr_a += (start_idx * R) / 8;
    arr_b += (other_start_idx * R) / 8;
    
    // Misalignment values
    uint8_t mis_a = (start_idx * R) % 8;
    uint8_t mis_b = (other_start_idx * R) % 8;
    
    // Word extractor
    // 64-bit
    uint64_t (*word64_ext_a) (const uint8_t*, uint8_t);
    uint64_t (*word64_ext_b) (const uint8_t*, uint8_t);
    word64_ext_a = mis_a ? &DBRadixString::read_uint64_misaligned : &DBRadixString::read_uint64_aligned;
    word64_ext_b = mis_b ? &DBRadixString::read_uint64_misaligned : &DBRadixString::read_uint64_aligned;
    
    // 8-bit
    uint8_t (*word8_ext_a) (const uint8_t*, uint8_t);
    uint8_t (*word8_ext_b) (const uint8_t*, uint8_t);
    word8_ext_a = mis_a ? &DBRadixString::read_uint8_misaligned : &DBRadixString::read_uint8_aligned;
    word8_ext_b = mis_b ? &DBRadixString::read_uint8_misaligned : &DBRadixString::read_uint8_aligned;
    
    // Start Comparing
    size_t diff_idx = 0;
    size_t compare_count = 0; // For testing purposes
    
    // Check 64 bit style first
    for (; diff_idx < (max_offset * R / 64) * 64 / R; diff_idx += 64 / R) {
        compare_count++; // For testing purposes
        
        if (word64_ext_a(arr_a, mis_a) != word64_ext_b(arr_b, mis_b))
            break;
        arr_a += 8;
        arr_b += 8;
    }
    
    // Report complete subset
    if (diff_idx >= max_offset) {
        // std::cout << "\n Number of Comps: " << compare_count << "\n"; // For testing purposes
        return max_offset;
    }
    
    // Check 8 bit style next
    for (; diff_idx < max_offset; diff_idx += 8 / R) {
        compare_count++; // For testing purposes
        
        if (word8_ext_a(arr_a, mis_a) != word8_ext_b(arr_b, mis_b))
            break;
        arr_a += 1;
        arr_b += 1;
    }
    
    // Report complete subset
    if (diff_idx >= max_offset) {
        // std::cout << "\n Number of Comps: " << compare_count << "\n"; // For testing purposes
        return max_offset;
    }
    
    // Check R bit style finally
    uint8_t char_a = word8_ext_a(arr_a, mis_a);
    uint8_t char_b = word8_ext_b(arr_b, mis_b);
    uint8_t comp_mask = (((1 << R) - 1) << (8 - R));
    
    for (; diff_idx < max_offset; diff_idx += 1) {
        compare_count++; // For testing purposes
        
        if ((char_a & comp_mask) != (char_b & comp_mask))
            break;
        char_a <<= R;
        char_b <<= R;
    }
    
    
    // std::cout << "\n Number of Comps: " << compare_count << "\n"; // For testing purposes
    
    // Return first mismatch offset
    return diff_idx;
}

template <uint8_t R>
uint8_t DBRadixString<R>::first_char() const
{
    return (*(_string + (_start_offset * R) / 8) >> (8 - (_start_offset * R) % 8 - R)) & ((1 << R) - 1);
}

template <uint8_t R>
uint8_t DBRadixString<R>::char_at(size_t idx) const
{
    return ( *( _string + (_start_offset+idx) * R / 8 ) >>  (8 - ((_start_offset+idx) * R) % 8 - R) )    &     ((1 << R) - 1);
}



/************************** Start of DBRadixEdge *****************************/
template <int R, class V>
class DBRadixEdge
{
public:
    std::shared_ptr<DBRadixString<R>> path;
    size_t path_start, path_length;
    std::unique_ptr<DBRadixNode<R, V>> next_node;
    
    DBRadixEdge<R, V> (std::unique_ptr<DBRadixNode<R, V>> &node, std::unique_ptr<DBRadixString<R>> &&string, size_t start_i)
    : next_node(std::move(node)), path(std::move(string)), path_start(start_i), path_length(path->_length) {}
    
    DBRadixEdge<R, V> (std::unique_ptr<DBRadixNode<R, V>> &node, const std::shared_ptr<DBRadixString<R>> &string, size_t start_i, size_t length)
    : next_node(std::move(node)), path(string), path_start(start_i), path_length(length) {}
    
    ~DBRadixEdge<R, V>() { std::cout << "Deleting Edge: " << *path << " , start: " << path_start << " , length: " << path_length << "\n"; }
};



/************************** Start of DBRadixNode *****************************/
template <uint8_t R, class V>
class DBRadixNode
{
    std::unique_ptr<std::unique_ptr<DBRadixEdge<R, V>>[]> children;
    
public:
    bool is_leaf = false, is_wildcard = false, is_terminated = false;
    std::unique_ptr<V> value_ptr;
    
    // Constructor
    DBRadixNode<R, V> (bool is_leaf) : is_leaf(is_leaf)
    {
        if (!is_leaf)
            children.reset(new std::unique_ptr<DBRadixEdge<R, V>>[1 << R]);
    }

    ~DBRadixNode<R, V>() { std::cout << "Deleting Node: \n"; }
    
    // Public
    void make_parent()
    {
        if (is_leaf)
        {
            is_leaf = false;
            children.reset(new std::unique_ptr<DBRadixEdge<R, V>>[1 << R]);
        }
    }
    
    std::unique_ptr<DBRadixEdge<R, V>> &operator[](uint8_t idx) { return children[idx]; }
    const DBRadixEdge<R, V> *operator[](uint8_t idx) const { return children[idx].get(); }
    
    void print_node(std::ostream &os, uint16_t level, std::string &key, size_t key_idx, const std::string &tab = "  ")
    {
        constexpr uint64_t num_of_el_in_byte = 8 / R;
        
        for (int i = 0; i < level; i++) os << tab;
        os << "Node: " << (is_terminated ? "$ " : " ") << (is_wildcard ? "* " : " ") << "'";
        if (key_idx % num_of_el_in_byte)
            os << std::hex << "0x" << (uint16_t)key[key_idx / num_of_el_in_byte] << " " << std::dec;
        for (size_t ki = key_idx / num_of_el_in_byte - 1; ki != -1; ki--)
            os << key[ki];
        os << "'";
        
        if (!is_leaf)
        {
            //os << "\n"; for (int i = 0; i < level; i++) os << tab;
            os << "{\n";
            bool is_first = true;
            for (int i = 0; i < (1 << R); i++)
            {
                if (!children[i])
                    continue;
                
                if (!is_first)
                    os << ",\n";
                else
                    is_first = false;
                
                key.resize(div_round_up(key_idx + children[i]->path_length, num_of_el_in_byte), '\0');
                for (size_t idx = 0; idx < children[i]->path_length; idx++)
                {
                    uint8_t c = children[i]->path->char_at(idx + children[i]->path_start);
                    c <<= (num_of_el_in_byte - ((key_idx + idx) % num_of_el_in_byte) - 1) * R;
                    key[(key_idx + idx) / num_of_el_in_byte] = c | uint8_t(key[(key_idx + idx) / num_of_el_in_byte]);
                }
                children[i]->next_node->print_node(os, level+1, key, key_idx + children[i]->path_length, tab);
                key.resize(div_round_up(key_idx, num_of_el_in_byte));
                int shift_cnt = ((num_of_el_in_byte - (key_idx % num_of_el_in_byte)) * R) % 8;
                uint8_t c = 0xff;
                c >>= shift_cnt;
                c <<= shift_cnt;
                key[key_idx / num_of_el_in_byte] = c & uint8_t(key[key_idx / num_of_el_in_byte]);
            }
            os << "\n";
            for (int i = 0; i < level; i++) os << tab;
            os << "}";
        }
    }
};




/************************** Start of DBRadixTrie *****************************/

// Private
template <int R, class V>
inline DBRadixNode<R, V> *DBRadixTrie<R, V>::insert_new_node_without_conflict(DBRadixNode<R, V> &node, const DBRadixString<R> &tmp_key, const V& value, bool is_wildcard)
{
    // Create a new node
    std::unique_ptr<DBRadixNode<R, V>> new_node (new DBRadixNode<R, V>(true));
    new_node->is_terminated = true;
    new_node->is_wildcard = is_wildcard;
    new_node->value_ptr.reset(new V(value));
    
    // Create a copy of key
    std::unique_ptr<DBRadixString<R>> key (new DBRadixString<R>(tmp_key));
    
    // Create the edge and add it onto the node
    DBRadixNode<R, V> *new_node_ptr = new_node.get();
    uint8_t first_char = key->first_char();
    node[first_char] = std::unique_ptr<DBRadixEdge<R, V>> (new DBRadixEdge<R, V>(new_node, std::move(key), 0));
    
    return new_node_ptr;
    // Transfer ownership of the key
    //string_ptrs.push_back(std::move(key));
}

template <int R, class V>
inline DBRadixNode<R, V> * DBRadixTrie<R, V>::find_closest_node(DBRadixString<R>& key)
{
    DBRadixNode<R, V> *it = root_node.get();
    while (key._length) {
        if (it->is_leaf)
            return it;
        
        DBRadixEdge<R, V> *it_edge = (*it)[key.first_char()].get();
        if (!it_edge)
            return it;
        
        size_t shared_length = it_edge->path->compare(it_edge->path_start, it_edge->path_start + it_edge->path_length, key, 0);
        if (shared_length < it_edge->path_length)
            return it;
        
        key._start_offset += shared_length;
        key._length -= shared_length;
        
        it = it_edge->next_node.get();
    }
    
    return it;
}

template <int R, class V>
inline DBRadixNode<R, V> * DBRadixTrie<R, V>::find_closest_node_and_leaf(DBRadixString<R>& key)
{
    DBRadixNode<R, V> *it = root_node.get();
    //DBRadixNode<R, V> *leaf = root_node;
    while (key._length) {
        if (it->is_leaf)
            return it;
        
        DBRadixEdge<R, V> *it_edge = (*it)[key.first_char()].get();
        if (!it_edge)
            return it;
        
        size_t shared_length = it_edge->path->compare(it_edge->path_start, it_edge->path_start + it_edge->path_length, key, 0);
        if (shared_length < it_edge->path_length)
            return it;
        
        key._start_offset += shared_length;
        key._length -= shared_length;
        
        it = it_edge->next_node.get();
    }
    
    return it;
}

// Constructors
template <int R, class V>
DBRadixTrie<R, V>::DBRadixTrie() : root_node(new DBRadixNode<R, V>(false)) {}

template <int R, class V>
DBRadixTrie<R, V>::~DBRadixTrie()
{}

// Public
template <int R, class V>
void DBRadixTrie<R, V>::clear()
{
    root_node.reset(new DBRadixNode<R, V>(false));
    //string_ptrs.clear();
}

template <int R, class V>
void DBRadixTrie<R, V>::insert(const std::string &key, const V &value)
{
    // Wildcard char is '*' at the beginning of key
    bool is_wildcard = (key[0] == '*');
    const char *key_cstr = key.c_str() + ((key[0] == '*') & 1);
    
    // Find the closest node
    DBRadixString<R> tmp_key(key_cstr);
    DBRadixNode<R, V> *last_common_node = find_closest_node(tmp_key);
    
    // Check if key is consumed
    if (!tmp_key._length) {
        last_common_node->is_terminated = true;
        last_common_node->is_wildcard = is_wildcard;
        last_common_node->value_ptr.reset(new V(value));
        return;
    }
    
    // We need to create a new node, maybe!
    // Make the node a parent.
    last_common_node->make_parent();
    
    // Check if a conflicting child exists
    DBRadixEdge<R, V>*edge = (*last_common_node)[tmp_key.first_char()].get();
    
    // No conflict
    //std::cout << "Creating No conf node\n"; // Debug
    if (!edge) {
        insert_new_node_without_conflict(*last_common_node, tmp_key, value, is_wildcard);
        return;
    }
    
    // Conflict! Create a mitigating node and ammend the edge
    //std::cout << "Creating middle node\n"; // Debug
    size_t shared_length = edge->path->compare(edge->path_start, edge->path_start + edge->path_length, tmp_key, 0);
    std::unique_ptr<DBRadixNode<R, V>> middle_node_ptr (new DBRadixNode<R, V>(false));
    DBRadixNode<R, V> &middle_node = *middle_node_ptr;
    
    std::unique_ptr<DBRadixEdge<R, V>> middle_edge (new DBRadixEdge<R, V>(edge->next_node, edge->path, edge->path_start + shared_length, edge->path_length - shared_length));
    
    middle_node[edge->path->char_at(middle_edge->path_start)] = std::move(middle_edge);
    edge->next_node = std::move(middle_node_ptr);
    edge->path_length = shared_length;
    
    // Trim the key
    tmp_key._start_offset += shared_length; tmp_key._length -= shared_length;
    
    // Check if there's need for node creation.
    if (tmp_key._length)
        insert_new_node_without_conflict(middle_node, tmp_key, value, is_wildcard);
    else {
        middle_node.is_terminated = true;
        middle_node.is_wildcard = is_wildcard;
        middle_node.value_ptr.reset(new V(value));
    }
}

template <int R, class V>
const V *DBRadixTrie<R, V>::lookup(const std::string &str_key) const
{
    //std::cout << *this << "\n";
    // Allocate the values vector
    const V *value_ptr = nullptr;
    
    // Find the closest node
    DBRadixString<R> key(str_key);
    
    // Travel the tree, finding the most specific key, storing last value when wildcard.
    DBRadixNode<R, V> *it = root_node.get();
    while (key._length)
    {
        if (it->is_wildcard)
            value_ptr = it->value_ptr.get();
        
        if (it->is_leaf)
            break;
        
        DBRadixEdge<R, V> *it_edge = (*it)[key.first_char()].get();
        if (!it_edge)
            break;
        
        size_t shared_length = it_edge->path->compare(it_edge->path_start, it_edge->path_start + it_edge->path_length, key, 0);
        if (shared_length < it_edge->path_length)
            break;
        
        key._start_offset += shared_length;
        key._length -= shared_length;
        
        it = it_edge->next_node.get();
    }
    
    // Check if key is consumed and accepting
    if (!key._length && it->is_terminated)
        value_ptr = it->value_ptr.get();
    
    return value_ptr;
}

template <int R, class V>
V *DBRadixTrie<R, V>::lookup(const std::string &str_key)
{
    auto const_this = static_cast<const DBRadixTrie<R, V> *>(this);
    return const_cast<V *>(const_this->lookup(str_key));
}

template <int R, class V>
V& DBRadixTrie<R, V>::operator[](const std::string &key)
{
    // Wildcard char is '*' at the beginning of key
    bool is_wildcard = (key[0] == '*');
    const char *key_cstr = key.c_str() + ((key[0] == '*') & 1);
    
    // Find the closest node
    DBRadixString<R> tmp_key(key_cstr);
    DBRadixNode<R, V> *last_common_node = find_closest_node(tmp_key);
    
    // Check if key is consumed
    if (!tmp_key._length)
    {
        if (!last_common_node->is_terminated)
        {
            last_common_node->is_terminated = true;
            last_common_node->is_wildcard = is_wildcard;
            last_common_node->value_ptr.reset(new V());
        }
        return *(last_common_node->value_ptr);
    }
    
    // We need to create a new node, maybe!
    // Make the node a parent.
    last_common_node->make_parent();
    
    // Check if a conflicting child exists
    DBRadixEdge<R, V>*edge = (*last_common_node)[tmp_key.first_char()].get();
    
    // No conflict
    //std::cout << "Creating No conf node\n"; // Debug
    if (!edge)
        return *(insert_new_node_without_conflict(*last_common_node, tmp_key, {}, is_wildcard)->value_ptr);
    
    // Conflict! Create a mitigating node and ammend the edge
    //std::cout << "Creating middle node\n"; // Debug
    size_t shared_length = edge->path->compare(edge->path_start, edge->path_start + edge->path_length, tmp_key, 0);
    std::unique_ptr<DBRadixNode<R, V>> middle_node_ptr (new DBRadixNode<R, V>(false));
    DBRadixNode<R, V> &middle_node = *middle_node_ptr;
    
    std::unique_ptr<DBRadixEdge<R, V>> middle_edge (new DBRadixEdge<R, V>(edge->next_node, edge->path, edge->path_start + shared_length, edge->path_length - shared_length));
    
    uint8_t int_char = edge->path->char_at(middle_edge->path_start);
    middle_node[int_char] = std::move(middle_edge);
    edge->next_node = std::move(middle_node_ptr);
    edge->path_length = shared_length;
    
    // Trim the key
    tmp_key._start_offset += shared_length; tmp_key._length -= shared_length;
    
    // Check if there's need for node creation.
    if (tmp_key._length)
        return *(insert_new_node_without_conflict(middle_node, tmp_key, {}, is_wildcard)->value_ptr);
    else {
        middle_node.is_terminated = true;
        middle_node.is_wildcard = is_wildcard;
        middle_node.value_ptr.reset(new V());
        return *(middle_node.value_ptr);
    }
}

template <int R, class V>
const V& DBRadixTrie<R, V>::operator[](const std::string &key) const
{
    const V *value_ptr = lookup(key);
    if (value_ptr)
        return *value_ptr;
    
    throw Exception("Accessor called for non existent key: " + key + ", while in const mode!!!");
}

template <int R, class V>
std::ostream & operator<<(std::ostream &os, const DBRadixTrie<R, V> &trie)
{
    os << "DBRadixTrie <" << R << ", " << typeid(V).name() << "> : \n{\n";
    std::string key;
    trie.root_node->print_node(os, 1, key, 0);
    os << "\n}";
    return os;
}
