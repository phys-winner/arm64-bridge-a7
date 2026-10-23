# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(asphalt7_arm64_bridge LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ASPHALT7_GL_TELEMETRY
       "Keep bounded GL capability/upload/viewport/error telemetry for diagnostics"
       OFF)

option(ASPHALT7_VFS_TELEMETRY
       "Keep per-operation embedded VFS telemetry for diagnostics"
       OFF)

option(ASPHALT7_JNI_TELEMETRY
       "Keep repeated guest static-JNI export telemetry for diagnostics"
       OFF)

option(ASPHALT7_INPUT_TELEMETRY
       "Keep selected touch-event telemetry for input diagnostics"
       OFF)

option(ASPHALT7_FINAL_SILENT
       "Build the release bridge without host or guest diagnostic logging"
       OFF)

option(ASPHALT7_FAILURE_TELEMETRY
       "Keep only bridge/JNI failure reasons when final silence is enabled"
       OFF)

find_package(Git REQUIRED)

# The Android-facing library must be libAndroid.so because the original Java
# code calls System.loadLibrary("Android"). Keep the guest as an A32 image;
# the final shared object is the AArch64 host loaded by Android.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)
set(Boost_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost/libs/config/include"
    CACHE PATH "Boost submodule configuration headers" FORCE)
file(GLOB BOOST_HEADER_DIRS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost/libs/*/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost/libs/numeric/*/include")
set(DYNARMIC_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dynarmic")
if(NOT EXISTS "${DYNARMIC_SOURCE_DIR}/CMakeLists.txt" OR
   NOT EXISTS "${Boost_INCLUDE_DIR}/boost/version.hpp")
    message(FATAL_ERROR "Initialize dependencies with git submodule update --init --recursive")
endif()

# Apply Android changes to a build copy so the pinned submodule stays clean.
set(DYNARMIC_PATCHED_DIR "${CMAKE_CURRENT_BINARY_DIR}/dynarmic-patched")
file(COPY "${DYNARMIC_SOURCE_DIR}/" DESTINATION "${DYNARMIC_PATCHED_DIR}"
    PATTERN ".git" EXCLUDE)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" apply --unsafe-paths
            "--directory=${DYNARMIC_PATCHED_DIR}"
            "${CMAKE_CURRENT_SOURCE_DIR}/patches/dynarmic-android.patch"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
    RESULT_VARIABLE DYNARMIC_PATCH_RESULT)
if(NOT DYNARMIC_PATCH_RESULT EQUAL 0)
    message(FATAL_ERROR "Could not apply the Dynarmic Android patch")
endif()
add_subdirectory("${DYNARMIC_PATCHED_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/dynarmic")
target_include_directories(dynarmic SYSTEM PRIVATE ${BOOST_HEADER_DIRS})
if(ASPHALT7_FINAL_SILENT)
    target_compile_definitions(dynarmic PRIVATE ASPHALT7_FINAL_SILENT=1)
endif()

set(BRIDGE_SOURCES
    src/graphics_settings.cpp
    src/postprocess_aa.cpp
    src/asset_vfs.cpp
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    src/thunks_gl.cpp
    src/thunks_gl_gles2_core.cpp
    src/thunks_libc.cpp
    src/thunks_opensles.cpp
    src/jni_fake_env.cpp
    src/jni_bridge.cpp
    src/offline_academy.cpp
)

add_library(Android SHARED ${BRIDGE_SOURCES})

target_include_directories(Android PRIVATE
    src
)
target_include_directories(Android SYSTEM PRIVATE ${BOOST_HEADER_DIRS})

target_compile_definitions(Android PRIVATE ANDROID __ANDROID__)
if(ASPHALT7_GL_TELEMETRY)
    target_compile_definitions(Android PRIVATE ASPHALT7_GL_TELEMETRY=1)
endif()
if(ASPHALT7_VFS_TELEMETRY)
    target_compile_definitions(Android PRIVATE ASPHALT7_VFS_TELEMETRY=1)
endif()
if(ASPHALT7_JNI_TELEMETRY)
    target_compile_definitions(Android PRIVATE ASPHALT7_JNI_TELEMETRY=1)
endif()
if(ASPHALT7_INPUT_TELEMETRY)
    target_compile_definitions(Android PRIVATE ASPHALT7_INPUT_TELEMETRY=1)
endif()
if(ASPHALT7_FINAL_SILENT)
    target_compile_definitions(Android PRIVATE ASPHALT7_FINAL_SILENT=1)
endif()
if(ASPHALT7_FAILURE_TELEMETRY)
    target_compile_definitions(Android PRIVATE ASPHALT7_FAILURE_TELEMETRY=1)
endif()
target_compile_options(Android PRIVATE
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -ffunction-sections
    -fdata-sections
)

target_link_libraries(Android PRIVATE
    dynarmic
    GLESv2
    EGL
    OpenSLES
    android
    m
    z
)
if(NOT ASPHALT7_FINAL_SILENT OR ASPHALT7_FAILURE_TELEMETRY)
    target_link_libraries(Android PRIVATE log)
endif()

# Android 15+ 16 KB devices require the host ELF's PT_LOAD segments to be
# compatible with 16 KB pages. Verify the produced ELF independently.
target_link_options(Android PRIVATE
    "-Wl,--gc-sections"
    "-Wl,--icf=all"
    "-Wl,--exclude-libs,ALL"
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,relro"
    "-Wl,-z,now"
)
