#include "ui.h"
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

void ui_init() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        init_pair(COLOR_TITLE, COLOR_CYAN, COLOR_BLACK);
        init_pair(COLOR_LABEL, COLOR_YELLOW, COLOR_BLACK);
        init_pair(COLOR_ACCENT, COLOR_MAGENTA, COLOR_BLACK);
        init_pair(COLOR_ERROR, COLOR_RED, COLOR_BLACK);
        init_pair(COLOR_SUCCESS, COLOR_GREEN, COLOR_BLACK);
        init_pair(COLOR_DIM, COLOR_WHITE, COLOR_BLACK);
        init_pair(COLOR_SELECTED, COLOR_BLACK, COLOR_WHITE);
        
        for (int i = 0; i <= 7; i++) {
            init_pair(10 + i, i, COLOR_BLACK);
        }
    }
}

void ui_cleanup() {
    endwin();
}

static WINDOW *current_log_win = NULL;

void ui_printf(const char *fmt, ...) {
    if (!current_log_win) return; // Ignore if no active window
    
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    // Strip ANSI codes before printing
    char stripped[1024];
    int j = 0;
    for (int i = 0; buffer[i] != '\0' && j < 1023; i++) {
        if (buffer[i] == '\x1b') {
            while (buffer[i] != '\0' && buffer[i] != 'm') i++;
            if (buffer[i] == '\0') break;
            continue;
        }
        stripped[j++] = buffer[i];
    }
    stripped[j] = '\0';
    
    wprintw(current_log_win, "%s", stripped);
    wrefresh(current_log_win);
}

int ui_select_menu(const char *title, const char **options, int option_count) {
    int selected = 0;
    int ch;
    
    while (1) {
        clear();
        
        attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
        mvprintw(2, 4, "%s", title);
        attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
        
        for (int i = 0; i < option_count; i++) {
            if (i == selected) {
                attron(COLOR_PAIR(COLOR_SELECTED));
            }
            mvprintw(4 + i, 6, "%d. %s", i + 1, options[i]);
            if (i == selected) {
                attroff(COLOR_PAIR(COLOR_SELECTED));
            }
        }
        
        attron(COLOR_PAIR(COLOR_DIM));
        mvprintw(6 + option_count, 4, "Use UP/DOWN arrows to navigate. Press ENTER to select. 'q' to quit.");
        attroff(COLOR_PAIR(COLOR_DIM));
        refresh();
        
        ch = getch();
        if (ch == KEY_UP && selected > 0) {
            selected--;
        } else if (ch == KEY_DOWN && selected < option_count - 1) {
            selected++;
        } else if (ch == '\n' || ch == KEY_ENTER) {
            return selected;
        } else if (ch == 'q' || ch == 'Q' || ch == ERR || ch == 3) {
            return -1;
        }
    }
}

void ui_input_dialog(const char *prompt, char *buffer, int max_len) {
    clear();
    attron(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    mvprintw(2, 4, "%s", prompt);
    attroff(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    
    curs_set(1);
    echo();
    mvgetnstr(4, 4, buffer, max_len - 1);
    noecho();
    curs_set(0);
}

void ui_show_message(const char *title, const char *msg) {
    clear();
    attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    mvprintw(2, 4, "%s", title);
    attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    
    mvprintw(4, 4, "%s", msg);
    
    attron(COLOR_PAIR(COLOR_DIM));
    mvprintw(6, 4, "Press any key to continue...");
    attroff(COLOR_PAIR(COLOR_DIM));
    refresh();
    getch();
}

// Sniffing UI globals
static WINDOW *sniff_win = NULL;

void ui_sniff_start(const char *device_name, const char *filter) {
    clear();
    attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    mvprintw(1, 2, "Capturing on: %s | Filter: %s", device_name, filter ? filter : "None");
    attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    
    attron(COLOR_PAIR(COLOR_DIM));
    mvprintw(3, 2, "Press Ctrl+C to stop capture.");
    attroff(COLOR_PAIR(COLOR_DIM));
    refresh();
    
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    sniff_win = newwin(max_y - 6, max_x - 4, 5, 2);
    scrollok(sniff_win, TRUE);
    current_log_win = sniff_win;
}

void ui_sniff_add_packet(const char *packet_summary) {
    if (sniff_win) {
        wprintw(sniff_win, "%s\n", packet_summary);
        wrefresh(sniff_win);
    }
}

void ui_sniff_log(const char *msg) {
    ui_sniff_add_packet(msg);
}

void ui_sniff_end() {
    if (sniff_win) {
        delwin(sniff_win);
        sniff_win = NULL;
        if (current_log_win == sniff_win) current_log_win = NULL;
    }
}

int ui_inspect_session_menu(int total_packets, summary_fetcher_t fetcher) {
    int selected = 0;
    int ch;
    
    int max_y, max_x;
    
    while (1) {
        getmaxyx(stdscr, max_y, max_x);
        clear();
        
        attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
        mvprintw(1, 2, "Inspecting Session (%d packets)", total_packets);
        attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
        
        attron(COLOR_PAIR(COLOR_DIM));
        mvprintw(2, 2, "UP/DOWN: Navigate | ENTER: View Details | 'q': Back");
        attroff(COLOR_PAIR(COLOR_DIM));
        
        int visible_lines = max_y - 5;
        if (visible_lines <= 0) visible_lines = 1;
        
        int start_idx = selected - (visible_lines / 2);
        if (start_idx > total_packets - visible_lines) start_idx = total_packets - visible_lines;
        if (start_idx < 0) start_idx = 0;
        
        for (int i = 0; i < visible_lines && (start_idx + i) < total_packets; i++) {
            int p_idx = start_idx + i;
            if (p_idx == selected) attron(COLOR_PAIR(COLOR_SELECTED));
            
            // fetcher returns a string for the packet summary
            mvprintw(4 + i, 2, "%s", fetcher(p_idx));
            
            if (p_idx == selected) attroff(COLOR_PAIR(COLOR_SELECTED));
        }
        
        refresh();
        ch = getch();
        
        if (ch == KEY_UP && selected > 0) selected--;
        else if (ch == KEY_DOWN && selected < total_packets - 1) selected++;
        else if (ch == '\n' || ch == KEY_ENTER) return selected;
        else if (ch == 'q' || ch == 'Q' || ch == ERR || ch == 3) return -1;
    }
}

static void waddstr_ansi(WINDOW *win, const char *str) {
    int bold = 0, dim = 0;
    int fg = 7; // white
    wattrset(win, COLOR_PAIR(10 + fg));

    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\x1b' && str[i+1] == '[') {
            i += 2;
            int val = 0;
            while (str[i] != '\0' && str[i] != 'm') {
                if (str[i] >= '0' && str[i] <= '9') {
                    val = val * 10 + (str[i] - '0');
                } else if (str[i] == ';') {
                    if (val == 0) { bold = 0; dim = 0; fg = 7; }
                    else if (val == 1) bold = 1;
                    else if (val == 2) dim = 1;
                    else if (val >= 30 && val <= 37) fg = val - 30;
                    val = 0;
                }
                i++;
            }
            if (str[i] == 'm') {
                if (val == 0) { bold = 0; dim = 0; fg = 7; }
                else if (val == 1) bold = 1;
                else if (val == 2) dim = 1;
                else if (val >= 30 && val <= 37) fg = val - 30;
                
                int attr = COLOR_PAIR(10 + fg);
                if (bold) attr |= A_BOLD;
                if (dim) attr |= A_DIM;
                wattrset(win, attr);
            } else if (str[i] == '\0') {
                break;
            }
            continue;
        }
        waddch(win, (unsigned char)str[i]);
    }
    wattrset(win, A_NORMAL);
}

int ui_show_packet_details(const char *details_text) {
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    clear();
    
    attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    mvprintw(1, 2, "Packet Details");
    attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    
    attron(COLOR_PAIR(COLOR_DIM));
    mvprintw(2, 2, "UP/DOWN: Scroll | 'q' or ENTER: Go Back | 'k': Snipe | '?': AI Insight");
    attroff(COLOR_PAIR(COLOR_DIM));
    
    refresh(); // FLUSH stdscr so the first getch() doesn't overwrite the pad with blank spaces!
    
    WINDOW *pad = newpad(2000, max_x - 3);
    current_log_win = pad;
    
    if (details_text) {
        wmove(pad, 0, 0);
        waddstr_ansi(pad, details_text);
    }
    
    int pad_y = 0;
    int ch;
    while (1) {
        prefresh(pad, pad_y, 0, 4, 2, max_y - 2, max_x - 2);
        ch = getch();
        if (ch == KEY_DOWN && pad_y < 1900) pad_y++; // simplify scrolling bound
        else if (ch == KEY_UP && pad_y > 0) pad_y--;
        else if (ch == 'q' || ch == 'Q' || ch == '\n' || ch == KEY_ENTER || ch == 'k' || ch == 'K' || ch == '?' || ch == ERR || ch == 3) {
            delwin(pad);
            current_log_win = NULL;
            return ch;
        }
    }
}

void ui_show_dashboard(session_stats_t *stats) {
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    clear();
    
    attron(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    mvprintw(1, 2, "=== Network Statistics Dashboard ===");
    attroff(COLOR_PAIR(COLOR_TITLE) | A_BOLD);
    
    attron(COLOR_PAIR(COLOR_DIM));
    mvprintw(2, 2, "Press 'q' or ENTER to go back");
    attroff(COLOR_PAIR(COLOR_DIM));
    
    double pps = stats->total_packets / stats->duration_seconds;
    double mbps = (stats->total_bytes * 8.0) / (stats->duration_seconds * 1000000.0);
    
    attron(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    mvprintw(4, 2, "[ Overall Metrics ]");
    attroff(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    
    mvprintw(5, 4, "Total Packets : %d", stats->total_packets);
    mvprintw(6, 4, "Total Volume  : %.2f MB", stats->total_bytes / 1000000.0);
    mvprintw(7, 4, "Duration      : %.2f seconds", stats->duration_seconds);
    mvprintw(8, 4, "Bandwidth     : %.2f Mbps  |  %.2f Packets/sec", mbps, pps);
    
    attron(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    mvprintw(10, 2, "[ Protocol Breakdown ]");
    attroff(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    
    int t = stats->total_packets;
    if (t == 0) t = 1;
    
    mvprintw(11, 4, "TCP   : %-6d (%.1f%%)", stats->count_tcp, (stats->count_tcp * 100.0) / t);
    mvprintw(12, 4, "UDP   : %-6d (%.1f%%)", stats->count_udp, (stats->count_udp * 100.0) / t);
    mvprintw(13, 4, "ICMP  : %-6d (%.1f%%)", stats->count_icmp, (stats->count_icmp * 100.0) / t);
    mvprintw(14, 4, "Other : %-6d (%.1f%%)", stats->count_other, (stats->count_other * 100.0) / t);
    
    mvprintw(11, 35, "HTTP  : %d", stats->count_http);
    mvprintw(12, 35, "HTTPS : %d", stats->count_https);
    mvprintw(13, 35, "DNS   : %d", stats->count_dns);
    
    attron(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    mvprintw(16, 2, "[ Top Talkers (By Total Volume) ]");
    attroff(COLOR_PAIR(COLOR_LABEL) | A_BOLD);
    
    mvprintw(17, 4, "%-16s | %-12s | %-12s", "IP Address", "Sent", "Received");
    mvprintw(18, 4, "-----------------|--------------|--------------");
    
    for (int i = 0; i < stats->top_talker_count; i++) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &stats->top_talkers[i].ip, ip_str, INET_ADDRSTRLEN);
        
        char sent[32], recv[32];
        if (stats->top_talkers[i].bytes_sent > 1000000) snprintf(sent, sizeof(sent), "%.2f MB", stats->top_talkers[i].bytes_sent / 1000000.0);
        else snprintf(sent, sizeof(sent), "%.2f KB", stats->top_talkers[i].bytes_sent / 1000.0);
        
        if (stats->top_talkers[i].bytes_recv > 1000000) snprintf(recv, sizeof(recv), "%.2f MB", stats->top_talkers[i].bytes_recv / 1000000.0);
        else snprintf(recv, sizeof(recv), "%.2f KB", stats->top_talkers[i].bytes_recv / 1000.0);
        
        mvprintw(19 + i, 4, "%-16s | %-12s | %-12s", ip_str, sent, recv);
    }
    
    refresh();
    while (1) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q' || ch == '\n' || ch == KEY_ENTER || ch == ERR || ch == 3) {
            break;
        }
    }
}
