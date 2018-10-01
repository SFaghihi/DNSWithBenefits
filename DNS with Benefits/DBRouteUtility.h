//
//  DBRouteUtility.h
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/19/18.
//  Copyright © 2018 sorco. All rights reserved.
//

#ifndef DBRouteUtility_h
#define DBRouteUtility_h

#include <stdio.h>

void interfaces(int nflag = 1);
void print_rtmsg(struct rt_msghdr *rtm, int nflag = 1);
    
#endif /* DBRouteUtility_h */
