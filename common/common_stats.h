// This work is based on:
// https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
// The files were modified 14.6.2024 by Richard Hyroš
// There is no warranty of any kind

#ifndef COMMON_STATS_H
#define COMMON_STATS_H

/**
 * @brief Thread function for basic stats. Exits when global_exit is set.
 * 
 * @param arg struct xsk_socket_info *xsk as thread data
 * @return NULL
 */
void *stats_poll(void *arg);

#endif // COMMON_STATS_H