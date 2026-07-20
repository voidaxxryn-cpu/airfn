#pragma once

#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../communication/shared_structs.hpp"

#define ROOT_MODE_LOGGING

namespace logging {
    /**
     * @brief Initializes the root logger.
     *
     * This function sets up the necessary resources and configurations for the logging system.
     * It prepares the logger for use in the root mode.
     *
     * @return project_status The status of the initialization (e.g., success or failure).
     */
    project_status init_root_logger();

    // Exposed API's

    /**
     * @brief Outputs a formatted log message.
     *
     * This function behaves like a printf-style function, allowing formatted text to be logged.
     * The function takes a format string followed by any additional arguments for formatting.
     *
     * @param fmt The format string (printf-style).
     * @param ... Additional arguments to be used with the format string.
     */
    void root_printf(const char* fmt, ...);

    /**
     * @brief Outputs the root logs to a specified buffer.
     *
     * This function retrieves and stores log entries into the user-provided buffer. It
     * will also handle any necessary communication with the logging subsystem.
     *
     * @param user_message_buffer The buffer where the log entries will be written.
     * @param user_cr3 The current CR3 value of the user, used for context.
     * @param message_count The number of log messages to retrieve and store in the buffer.
     */
    void output_root_logs(log_entry_t* user_message_buffer, uint64_t user_cr3, uint32_t message_count);
};
