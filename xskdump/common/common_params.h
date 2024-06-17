// This work is based on:
// https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
// The files were modified 14.6.2024 by Richard Hyroš
// There is no warranty of any kind

/* This common_user.h is used by userspace programs */
#ifndef __COMMON_PARAMS_H
#define __COMMON_PARAMS_H

#include <getopt.h>
#include "common_defines.h"

struct option_wrapper {
  struct option option;
  char *help;
  char *metavar;
  bool required;
};

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full);

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *long_options,
                        struct config *cfg, const char *doc);

#endif /* __COMMON_PARAMS_H */
