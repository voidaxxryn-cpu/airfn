#pragma once
#include "../project_includes.hpp"
#include "shellcode.hpp"

namespace communication {

    /**
     * @brief Initializes communication with the driver.
     *
     * This function sets up the necessary resources and configurations to
     * establish communication with a driver, using the provided driver base address
     * and its size.
     *
     * @param driver_base A pointer to the base address of the driver in memory.
     * @param driver_size The size of the driver in memory.
     * @return project_status The status of the initialization process.
     *         Returns status_success if successful, or an error code otherwise.
     */
    project_status init_communication(void* driver_base, uint64_t driver_size);

    /**
     * @brief Unhooks the data pointer associated with the driver.
     *
     * This function performs necessary cleanup and unhooks the data pointer
     * to prevent any further interaction with the driver.
     *
     * @return project_status The status of the unhooking process.
     *         Returns status_success if successful, or an error code otherwise.
     */
    project_status unhook_data_ptr(void);

};
