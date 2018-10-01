//
//  DBCommon.cpp
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/20/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#include "DBCommon.hpp"
#include "DBMatchSystemImp.hpp"

//template class DBRadixTrie<Trie_Radix, pre_callback_fnc_t>;
//template class DBRadixTrie<Trie_Radix, post_callback_fnc_t>;

template std::ostream & operator<< <Trie_Radix, post_callback_fnc_t> (std::ostream &os, const DBRadixTrie<Trie_Radix, post_callback_fnc_t> &trie);
template std::ostream & operator<< <Trie_Radix, pre_callback_fnc_t> (std::ostream &os, const DBRadixTrie<Trie_Radix, pre_callback_fnc_t> &trie);

template class DBMatchSystem<Trie_Radix, pre_callback_fnc_t>;
template class DBMatchSystem<Trie_Radix, post_callback_fnc_t>;
