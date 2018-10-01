//
//  DBRadixTrie.hpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 5/27/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBRadixTrie_hpp
#define DBRadixTrie_hpp

#include <iostream>
#include <memory>
#include <vector>
#include <optional>

template <uint8_t R, class V> class DBRadixNode;
template <uint8_t R> class DBRadixString;

/************************** Start of DBRadixTrie *****************************/
template <int R, class V>
class DBRadixTrie
{
    std::unique_ptr<DBRadixNode<R, V>> root_node;
    
    inline DBRadixNode<R, V> *insert_new_node_without_conflict(DBRadixNode<R, V> &node, const DBRadixString<R> &tmp_key, const V& value, bool is_wildcard);
    inline DBRadixNode<R, V> *find_closest_node(DBRadixString<R>& key);
    inline DBRadixNode<R, V> *find_closest_node_and_leaf(DBRadixString<R>& key);
    
public:
    DBRadixTrie<R, V>();
    ~DBRadixTrie<R, V>();
    
    void clear();
    void insert(const std::string &key, const V &value);
    void remove(const std::string &key);
    V pop(const std::string &key);
    
    V *lookup(const std::string &key);
    const V *lookup(const std::string &key) const;
    
    V& operator[](const std::string &key);
    const V& operator[](const std::string &key) const;
    
    template <int FR, class FV>
    friend std::ostream & operator<<(std::ostream &os, const DBRadixTrie<FR, FV> &trie);
};

#endif /* DBRadixTrie_hpp */
