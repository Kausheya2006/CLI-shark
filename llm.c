#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

typedef struct {
    char *memory;
    size_t size;
} MemoryStruct;

// Callback function used by libcurl to save the response
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0;  // out of memory

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// A helper to safely escape quotes and newlines for JSON
// A bulletproof helper to safely escape quotes and strip ALL illegal control bytes
char* escape_for_json(const char* input) {
    // Allocate double the size just to be safe
    char *escaped = malloc(strlen(input) * 2 + 1);
    if (!escaped) return NULL;
    
    int j = 0;
    for (int i = 0; input[i] != '\0'; i++) {
        // Cast to unsigned char to safely evaluate byte boundaries
        unsigned char c = (unsigned char)input[i]; 

        if (c == '"') {
            escaped[j++] = '\\'; escaped[j++] = '"';
        } else if (c == '\\') {
            escaped[j++] = '\\'; escaped[j++] = '\\';
        } else if (c == '\n') {
            escaped[j++] = '\\'; escaped[j++] = 'n';
        } else if (c == '\r') {
            escaped[j++] = '\\'; escaped[j++] = 'r';
        } else if (c == '\t') {
            escaped[j++] = '\\'; escaped[j++] = 't';
        } else if (c < 32 || c >= 127) {
            // CRITICAL FIREWALL: 
            // ASCII < 32 includes \x1b (ESC), \b (Backspace), \0 (Null), etc.
            // ASCII >= 127 strips out DEL and weird extended binary characters.
            // We just 'continue' to drop them completely!
            continue; 
        } else {
            escaped[j++] = c;
        }
    }
    escaped[j] = '\0';
    return escaped;
}

// Extracts the AI's message from the JSON and formats escaped characters
void refine_response(const char *raw_json) {
    const char *key = "\"content\":\"";
    char *start = strstr(raw_json, key);
    
    if (!start) {
        printf("\n[CLI-SHARK] Failed to parse AI response. Raw data:\n%s\n", raw_json);
        return;
    }

    start += strlen(key); // Move the pointer past the "content":" key

    printf("\n================= CLI-SHARK AI ANALYSIS =================\n");

    // Loop through the string character by character
    for (const char *p = start; *p != '\0'; p++) {
        // If we hit a quote that is NOT escaped, we have reached the end of the content string
        if (*p == '"') {
            break; 
        }

        // If we hit an escape slash '\', we need to translate the next character
        if (*p == '\\') {
            p++; // Move forward to the character after the slash
            if (*p == '\0') break; // Safety check to prevent reading out of bounds

            switch (*p) {
                case 'n':  putchar('\n'); break; // Print actual newline
                case 't':  putchar('\t'); break; // Print actual tab
                case 'r':  putchar('\r'); break; // Print carriage return
                case '"':  putchar('"');  break; // Print actual quote (removes the slash)
                case '\\': putchar('\\'); break; // Print a single slash
                default:   putchar(*p);   break; // Fallback: just print the character
            }
        } 
        // Normal characters get printed exactly as they are
        else {
            putchar(*p);
        }
    }
    
    printf("\n=========================================================\n\n");
}

// The main function to trigger the API
void send_to_llm_api(const char* raw_prompt) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk;
    chunk.memory = malloc(1);  // will be grown as needed
    chunk.size = 0;

    // Escape the prompt for JSON
    char* escaped_prompt = escape_for_json(raw_prompt);

    // Build the JSON payload for Ollama
    char json_payload[8192];
    snprintf(json_payload, sizeof(json_payload),
        "{\"model\": \"llama3\", \"messages\": [{\"role\": \"user\", \"content\": \"%s\"}], \"stream\": false}", 
        escaped_prompt);
    free(escaped_prompt); // Free the escaped string, we don't need it anymore

    // Initialize cURL
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        // Point to the local Ollama API endpoint
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:11434/api/chat");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
        
        // Tell cURL to send the response to our callback function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        printf("\n[CLI-SHARK] Asking local Ollama...\n");

        // 4. Perform the request!
        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fprintf(stderr, "Is Ollama running? Try running 'ollama run llama3' in another terminal.\n");
        } else {
            // Success! 
            refine_response(chunk.memory);
        }

        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    
    free(chunk.memory);
    curl_global_cleanup();
}