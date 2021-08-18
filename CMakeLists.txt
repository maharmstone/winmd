cmake_minimum_required(VERSION 3.15)

project(winmd VERSION 0.1.0)

# winmd.sys

set(SRC_FILES src/winmd.c
    src/io.c
    src/linear.c
    src/logger.c
    src/mountmgr.c
    src/pnp.c
    src/raid0.c
    src/raid10.c
    src/raid1.c
    src/raid45.c
    src/raid6.c
    ${CMAKE_CURRENT_BINARY_DIR}/winmd.rc)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC) # cmake bug 15170
    if(MSVC_C_ARCHITECTURE_ID STREQUAL "X86")
        set(CMAKE_SYSTEM_PROCESSOR "x86")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "x64")
        set(CMAKE_SYSTEM_PROCESSOR "x86_64")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARMV7")
        set(CMAKE_SYSTEM_PROCESSOR "arm")
    elseif(MSVC_C_ARCHITECTURE_ID STREQUAL "ARM64")
        set(CMAKE_SYSTEM_PROCESSOR "aarch64")
    endif()
endif()

configure_file(src/winmd.rc.in winmd.rc)

add_library(winmd SHARED ${SRC_FILES})

if(MSVC)
    include_directories("$ENV{WindowsSdkDir}Include\\$ENV{WindowsSDKLibVersion}km")
elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND WIN32)
    include_directories("${CMAKE_FIND_ROOT_PATH}/usr/include/ddk")
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    add_definitions(-D_AMD64_)
    set(MS_ARCH "x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
    add_definitions(-D_X86_)
    set(MS_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    add_definitions(-D_ARM_)
    set(MS_ARCH "arm")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    add_definitions(-D_ARM64_)
    set(MS_ARCH "arm64")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-D_DEBUG)
endif()

if(NOT MSVC)
    target_compile_options(winmd PUBLIC -U__NO_INLINE__)
    add_definitions(-D__USE_MINGW_ANSI_STDIO=0)
    add_definitions(-D__INTRINSIC_DEFINED_InterlockedBitTestAndSet)
    add_definitions(-D__INTRINSIC_DEFINED_InterlockedBitTestAndReset)
endif()

add_definitions(-DNTDDI_VERSION=0x0A000007)

target_compile_definitions(winmd PUBLIC _KERNEL_MODE WIN9X_COMPAT_SPINLOCK)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_compile_options(winmd PUBLIC /Gz) # stdcall
    endif()

    target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\ntoskrnl.lib")
    target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\hal.lib")

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\bufferoverflowfastfailk.lib")
    else()
        target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\BufferOverflowK.lib")
    endif()

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}um\\${MS_ARCH}\\armrt.lib")
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
        target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}um\\${MS_ARCH}\\arm64rt.lib")
    endif()

    target_link_libraries(winmd "$ENV{WindowsSdkDir}Lib\\$ENV{WindowsSDKLibVersion}km\\${MS_ARCH}\\rtlver.lib")
    target_link_options(winmd PUBLIC /SUBSYSTEM:NATIVE /NODEFAULTLIB /MANIFEST:NO /Driver /ENTRY:DriverEntry)

    # strip out flags for MSVC's runtime checks
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
else()
    target_compile_options(winmd PUBLIC -Wall -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wno-unknown-pragmas -msse4.2)

    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(winmd PUBLIC -Werror=cast-function-type)
    elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        target_compile_options(winmd PUBLIC -Wno-pragma-pack) # ignore warning in mingw headers
    endif()

    target_link_libraries(winmd ntoskrnl hal gcc)
    target_link_options(winmd PUBLIC -nostdlib -Wl,--subsystem,native -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--exclude-all-symbols)

    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
        target_link_options(winmd PUBLIC -Wl,--entry,_DriverEntry@8)
    else()
        target_link_options(winmd PUBLIC -Wl,--entry,DriverEntry)
    endif()
endif()

set_target_properties(winmd PROPERTIES PREFIX "")
set_target_properties(winmd PROPERTIES SUFFIX ".sys")

# --------------------------------------

# install

install(TARGETS winmd DESTINATION bin)
