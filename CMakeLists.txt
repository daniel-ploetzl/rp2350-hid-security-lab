cmake_minimum_required(VERSION 3.13)

# This profile is only for testing USB pairing on an unprovisioned test board.
option(HID_LAB_DEVELOPMENT_BUILD "Build an unprotected RP2350 test image without OTP" OFF)
set(HID_LAB_DEV_AES_KEY "" CACHE FILEPATH "Disposable 32-byte AES key for a development image")

# Must be set before the SDK import, which selects the board. Without it the
# SDK silently falls back to the RP2040 Pico, which this project cannot target.
set(PICO_BOARD pico2_w CACHE STRING "Target board: pico2_w, or pico2 for no Wi-Fi")

include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(hid_lab C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(PICO_MBEDTLS_CONFIG_FILE "hid_lab_mbedtls_config.h" CACHE STRING
    "Mbed TLS configuration header used by the firmware")

# Production uses signed, encrypted SRAM boot and a locked OTP key page.
# Development embeds a disposable test key and omits both protections.
set(HID_LAB_SIGNING_KEY "" CACHE FILEPATH "Private secp256k1 signing key for the device family")
set(HID_LAB_AES_KEY "" CACHE FILEPATH "Per-device 32-byte AES key (keep outside this repository)")
set(HID_LAB_IV_SALT "" CACHE FILEPATH "Per-device 16-byte AES IV salt (keep outside this repository)")
if(HID_LAB_DEVELOPMENT_BUILD)
    if("${HID_LAB_DEV_AES_KEY}" STREQUAL "" OR NOT EXISTS "${HID_LAB_DEV_AES_KEY}")
        message(FATAL_ERROR "HID_LAB_DEV_AES_KEY must name a disposable 32-byte key file")
    endif()
else()
    foreach(key_file HID_LAB_SIGNING_KEY HID_LAB_AES_KEY HID_LAB_IV_SALT)
        if("${${key_file}}" STREQUAL "" OR NOT EXISTS "${${key_file}}")
            message(FATAL_ERROR "${key_file} must name an existing protected key file")
        endif()
    endforeach()
endif()

# Reserve the last four 4KB sectors for encrypted host pairing, input sequence, Wi-Fi
# and runtime config. Secure code is linked for SRAM and the packaged UF2 is checked.
# Keep the linker variable distinct from the board's true flash-size macro.
set(PICO_FLASH_SIZE_BYTES 0x003FC000)

pico_sdk_init()

if(NOT PICO_PLATFORM STREQUAL "rp2350-arm-s")
    message(FATAL_ERROR "supported profiles require RP2350 Cortex-M33 Secure platform, got ${PICO_PLATFORM}")
endif()

find_package(Python3 COMPONENTS Interpreter REQUIRED)
if(HID_LAB_DEVELOPMENT_BUILD)
    set(HID_LAB_DEV_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    set(HID_LAB_DEV_KEY_HEADER "${HID_LAB_DEV_GENERATED_DIR}/hid_lab_dev_aes_key.h")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${HID_LAB_DEV_AES_KEY}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_dev_aes_key.py"
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_dev_aes_key.py")
    file(MAKE_DIRECTORY "${HID_LAB_DEV_GENERATED_DIR}")
    execute_process(
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_dev_aes_key.py
                ${HID_LAB_DEV_AES_KEY} ${HID_LAB_DEV_KEY_HEADER}
        RESULT_VARIABLE HID_LAB_DEV_KEY_RESULT
    )
    if(NOT HID_LAB_DEV_KEY_RESULT EQUAL 0)
        message(FATAL_ERROR "Could not create the development key header")
    endif()
    execute_process(
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_dev_aes_key.py
                ${HID_LAB_DEV_AES_KEY} ${HID_LAB_DEV_KEY_HEADER}
        RESULT_VARIABLE HID_LAB_DEV_KEY_CHECK_RESULT
    )
    if(NOT HID_LAB_DEV_KEY_CHECK_RESULT EQUAL 0)
        message(FATAL_ERROR "Development key header does not match the selected AES key")
    endif()
endif()

add_executable(hid_lab
    src/main.c
	src/input_tasks.c
    src/reactivation.c
    src/input_sequence.c
    src/secure_store.c
    src/pairing.c
    src/pairing_storage.c
    src/usb_descriptors.c
)

target_compile_options(hid_lab PRIVATE
    -Wall
    -Wextra
    -Werror
)

# Test only: milliseconds until the elapsed run time wraps. Leave at 0 for normal builds.
set(HID_LAB_TEST_WRAP_LEAD_MS 0 CACHE STRING "Test only: ms until elapsed run time wraps")

# Test only: fails an assertion at boot, to prove assertions survive Release builds.
option(HID_LAB_TEST_ASSERT "Test only: fail an assertion at boot" OFF)

# Exposes the linker region size to the build-time layout checks in src/main.c.
target_compile_definitions(hid_lab PRIVATE
    HID_LAB_SECURE_BUILD=$<NOT:$<BOOL:${HID_LAB_DEVELOPMENT_BUILD}>>
    HID_LAB_DEVELOPMENT_BUILD=$<BOOL:${HID_LAB_DEVELOPMENT_BUILD}>
    HID_LAB_LINK_FLASH_BYTES=${PICO_FLASH_SIZE_BYTES}
    HID_LAB_TEST_WRAP_LEAD_MS=${HID_LAB_TEST_WRAP_LEAD_MS}u
    HID_LAB_TEST_ASSERT=$<BOOL:${HID_LAB_TEST_ASSERT}>
)

target_include_directories(hid_lab PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)
if(HID_LAB_DEVELOPMENT_BUILD)
    target_include_directories(hid_lab PRIVATE ${HID_LAB_DEV_GENERATED_DIR})
endif()

target_link_libraries(hid_lab
    pico_stdlib
    pico_rand
    hardware_flash
    tinyusb_device
    tinyusb_board
    pico_mbedtls_crypto
    pico_mbedtls_headers
)

# Wi-Fi is built only for boards with a radio. inc/wifi_manager.h stubs it otherwise.
if(PICO_CYW43_SUPPORTED)
    target_sources(hid_lab PRIVATE src/wifi_manager.c)
    target_compile_definitions(hid_lab PRIVATE HID_LAB_WIFI=1)
    target_link_libraries(hid_lab pico_cyw43_arch_lwip_poll)
endif()

pico_set_binary_type(hid_lab no_flash)
pico_package_uf2_output(hid_lab 0x10000000)
if(NOT HID_LAB_DEVELOPMENT_BUILD)
    pico_sign_binary(hid_lab "${HID_LAB_SIGNING_KEY}")
    pico_encrypt_binary(hid_lab "${HID_LAB_AES_KEY}" "${HID_LAB_IV_SALT}" EMBED OTP_KEY_PAGE 29)
endif()
pico_add_extra_outputs(hid_lab)
if(HID_LAB_DEVELOPMENT_BUILD)
    add_custom_command(TARGET hid_lab POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_firmware_uf2.py
                ${CMAKE_CURRENT_BINARY_DIR}/hid_lab.uf2
        COMMENT "Checking development UF2 stays below reserved settings sectors"
        VERBATIM
    )
else()
    add_custom_command(TARGET hid_lab POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/extend_otp_for_credentials.py
                ${CMAKE_CURRENT_BINARY_DIR}/hid_lab.otp.json
        COMMENT "Adding Secure-only credential key shares to the OTP provisioning file"
        VERBATIM
    )
    add_custom_command(TARGET hid_lab POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_firmware_uf2.py
                ${CMAKE_CURRENT_BINARY_DIR}/hid_lab.uf2
        COMMENT "Checking encrypted firmware UF2 stays below the reserved credential sectors"
        VERBATIM
    )
endif()
