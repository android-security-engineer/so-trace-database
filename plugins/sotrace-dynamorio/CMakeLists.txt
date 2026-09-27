cmake_minimum_required(VERSION 3.14)
project(sotrace_dynamorio C)

# Point CMake at the DynamoRIO package:
#   cmake -DDynamoRIO_DIR=/opt/DynamoRIO/cmake -B build
find_package(DynamoRIO REQUIRED)

# ---- sotrace_client shared library ----
add_library(sotrace_client SHARED sotrace_client.c)

configure_DynamoRIO_client(sotrace_client)
use_DynamoRIO_extension(sotrace_client drmgr)

# Optional: memory-access tracing (adds drreg + drutil, higher overhead)
option(SOTRACE_ENABLE_MEMORY "Instrument memory reads and writes" OFF)
if(SOTRACE_ENABLE_MEMORY)
    target_compile_definitions(sotrace_client PRIVATE SOTRACE_ENABLE_MEMORY=1)
    use_DynamoRIO_extension(sotrace_client drreg)
    use_DynamoRIO_extension(sotrace_client drutil)
endif()

install(TARGETS sotrace_client DESTINATION .)
