#ifndef __DUMP_PAGETABLES_H
#define __DUMP_PAGETABLES_H

#ifdef CONFIG_ARM64
#include  "dump_pagetables64.h"
#else
#include  "dump_pagetables32.h"
#endif

#include "../../r2k.h"
#endif
