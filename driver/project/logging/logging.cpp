#include "logging.hpp"
#include <ntstrsafe.h>

namespace logging {
    // Message buffer to store log entries
    log_entry_t messages[MAX_MESSAGES] = { 0 };

    // Indexes for the log buffer (circular queue)
    uint32_t head_idx = 0;
    uint32_t tail_idx = 0;

    /**
     * @brief Converts an integer to a string representation in a specified base.
     *
     * This function converts an integer value to a string based on the specified base
     * (e.g., base 10 for decimal, base 16 for hexadecimal).
     *
     * @tparam T The type of the value to be converted.
     * @param value The integer value to convert.
     * @param result The buffer where the resulting string will be stored.
     * @param base The base for the conversion (between 2 and 36).
     * @param upper Boolean indicating whether the output should use uppercase letters
     *              (only relevant for base 16).
     * @return char* A pointer to the resulting string.
     */
    template <typename T>
    char* lukas_itoa(T value, char* result, int base, bool upper = false) {
        // Check that the base is valid
        if (base < 2 || base > 36) {
            *result = '\0';
            return result;
        }

        char* ptr = result, * ptr1 = result, tmp_char;
        T tmp_value;

        if (upper) {
            do {
                tmp_value = value;
                value /= base;
                *ptr++ = "ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    [35 + (tmp_value - value * base)];
            } while (value);
        }
        else {
            do {
                tmp_value = value;
                value /= base;
                *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz"
                    [35 + (tmp_value - value * base)];
            } while (value);
        }

        // Apply negative sign
        if (tmp_value < 0)
            *ptr++ = '-';

        *ptr-- = '\0';
        while (ptr1 < ptr) {
            tmp_char = *ptr;
            *ptr-- = *ptr1;
            *ptr1++ = tmp_char;
        }

        return result;
    }

    /**
     * @brief Copies a string to a buffer with bounds checking.
     *
     * This function copies the source string into the provided buffer until the buffer
     * is full or the string ends.
     *
     * @param buffer The destination buffer to copy the string into.
     * @param src The source string to copy.
     * @param idx The index in the buffer where the next character will be written.
     * @return true If the buffer is full and the string couldn't be fully copied.
     * @return false If the string was successfully copied into the buffer.
     */
    bool logger_format_copy_str(char* const buffer, char const* const src, uint32_t& idx) {
        for (uint32_t i = 0; src[i]; ++i) {
            buffer[idx++] = src[i];

            // Check if buffer end has been reached
            if (idx >= MAX_MESSAGE_SIZE - 1) {
                buffer[MAX_MESSAGE_SIZE] = '\0';
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Formats a string and stores it in a buffer.
     *
     * This function formats a string into the provided buffer using a subset of printf
     * specifiers, including %s, %i, %d, %u, %x, %X, and %p.
     *
     * @param buffer The destination buffer to store the formatted string.
     * @param format The format string.
     * @param args The arguments to format.
     */
    void logger_format(char* const buffer, char const* const format, va_list& args) {
        uint32_t buffer_idx = 0;
        uint32_t format_idx = 0;

        // True if the last character was a '%'
        bool specifying = false;

        while (true) {
            auto const c = format[format_idx++];

            // End of format string
            if (c == '\0')
                break;

            if (c == '%') {
                specifying = true;
                continue;
            }

            // Copy the character directly
            if (!specifying) {
                buffer[buffer_idx++] = c;

                // Check if buffer end has been reached
                if (buffer_idx >= MAX_MESSAGE_SIZE - 1)
                    break;

                specifying = false;
                continue;
            }

            char fmt_buffer[128];

            // Format the string according to the specifier
            switch (c) {
            case 's': {
                if (logger_format_copy_str(buffer, va_arg(args, char const*), buffer_idx))
                    return;
                break;
            }
            case 'd':
            case 'i': {
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, int), fmt_buffer, 10), buffer_idx))
                    return;
                break;
            }
            case 'u': {
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 10), buffer_idx))
                    return;
                break;
            }
            case 'x': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 16), buffer_idx))
                    return;
                break;
            }
            case 'X': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, unsigned int), fmt_buffer, 16, true), buffer_idx))
                    return;
                break;
            }
            case 'p': {
                if (logger_format_copy_str(buffer, "0x", buffer_idx))
                    return;
                if (logger_format_copy_str(buffer,
                    lukas_itoa(va_arg(args, uint64_t), fmt_buffer, 16, true), buffer_idx))
                    return;
                break;
            }
            }

            specifying = false;
        }

        buffer[buffer_idx] = '\0';
    }

    // Exposed API'S

    /**
     * @brief Prints a formatted message to the root logger.
     *
     * This function uses printf-style formatting to log a message. The message is stored
     * in a circular buffer, and the oldest log entry will be overwritten when the buffer
     * is full.
     *
     * @param fmt The format string for the log message.
     */
    void root_printf(const char* fmt, ...) {
#ifndef ROOT_MODE_LOGGING
        return;
#endif // !ROOT_MODE_LOGGING

        // Check if the buffer is full and move the tail index ahead if necessary
        if ((head_idx + 1) % MAX_MESSAGES == tail_idx) {
            tail_idx = (tail_idx + 1) % MAX_MESSAGES;
        }

        log_entry_t* curr_entry = &messages[head_idx];
        curr_entry->present = true;

        va_list args;
        va_start(args, fmt);
        logger_format(curr_entry->payload, fmt, args);
        va_end(args);

        head_idx = (head_idx + 1) % MAX_MESSAGES;
    }

    /**
     * @brief Retrieves and stores log messages into the user-provided buffer.
     *
     * This function retrieves log messages from the internal message buffer and copies
     * them to the user-specified buffer. It ensures that no more than the requested number
     * of messages are copied, and it handles communication with the physical memory.
     *
     * @param user_message_buffer The buffer where the log entries will be written.
     * @param user_cr3 The current CR3 value of the user, used for context.
     * @param message_count The number of messages to retrieve.
     */
    void output_root_logs(log_entry_t* user_message_buffer, uint64_t user_cr3, uint32_t message_count) {
#ifndef ROOT_MODE_LOGGING
        return;
#endif // !ROOT_MODE_LOGGING

        uint32_t current_idx = tail_idx; // Oldest message
        uint32_t buffer_index = 0;

        while (current_idx != head_idx && buffer_index < message_count) {

            if (physmem::runtime::copy_memory_from_constructed_cr3(
                (void*)&user_message_buffer[buffer_index],  // Destination buffer
                (void*)&messages[current_idx],              // Source buffer
                sizeof(log_entry_t),
                user_cr3) != status_success) {
                return;
            }
            memset(&messages[buffer_index], 0, sizeof(messages[buffer_index]));

            buffer_index++;
            current_idx = (current_idx + 1) % MAX_MESSAGES;
        }

        tail_idx = head_idx;
    }

    /**
     * @brief Initializes the root logger.
     *
     * This function clears the message buffer and resets the head and tail indexes for
     * the circular queue.
     *
     * @return project_status The status of the initialization (e.g., success).
     */
    project_status init_root_logger() {

        memset(messages, 0, sizeof(messages));
        head_idx = 0;
        tail_idx = 0;

        return status_success;
    }
};
