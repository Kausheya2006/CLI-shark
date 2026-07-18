#ifndef UI_H
#define UI_H

#include <ncurses.h>
#include <pcap.h>
#include <stdarg.h>

// Color pairs
#define COLOR_TITLE 1
#define COLOR_LABEL 2
#define COLOR_ACCENT 3
#define COLOR_ERROR 4
#define COLOR_SUCCESS 5
#define COLOR_DIM 6
#define COLOR_SELECTED 7

// Initialize the ncurses UI
void ui_init();

// Cleanup and restore the terminal
void ui_cleanup();

// Custom printf that routes to the current active ncurses window/pad
void ui_printf(const char *fmt, ...);

// Display a menu and return the selected index (0-indexed).
// Returns -1 if cancelled (e.g., user hits 'q' or escape)
int ui_select_menu(const char *title, const char **options, int option_count);

// Display an input dialog to get a string from the user
void ui_input_dialog(const char *prompt, char *buffer, int max_len);

// Display a simple message box (press any key to continue)
void ui_show_message(const char *title, const char *msg);

// --- Live Sniffing UI ---
void ui_sniff_start(const char *device_name, const char *filter);
void ui_sniff_add_packet(const char *packet_summary);
void ui_sniff_log(const char *msg); // For printing errors/infos in the sniffing view
void ui_sniff_end();

// --- Session Inspection UI ---
// Returns the index of the selected packet, or -1 if user exits.
// Provides a callback to fetch summary strings so we don't pass massive arrays.
typedef const char* (*summary_fetcher_t)(int index);
int ui_inspect_session_menu(int total_packets, summary_fetcher_t fetcher);

// Render the dashboard using session_stats_t
// Since we don't want circular includes, we use a forward declaration or include report.h
struct session_stats_t; // Forward declare if needed, but it's better to just include it in ui.c or pass a void* if we avoid includes.
// Actually, I'll just include report.h here.
#include "report.h"
void ui_show_dashboard(session_stats_t *stats);

// Render the detailed report of a packet in a scrollable window
int ui_show_packet_details(const char *details_text);

#endif // UI_H
