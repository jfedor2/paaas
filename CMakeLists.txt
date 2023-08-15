cmake_minimum_required(VERSION 3.13)

add_compile_definitions(PICO_DEFAULT_UART_BAUD_RATE=921600)

set(PICO_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/pico-sdk")

set(PICO_BOARD pico_w)

include(pico_sdk_import.cmake)

project(paaas)

pico_sdk_init()

add_executable(paaas
    src/paaas.c
)
target_include_directories(paaas PRIVATE src)
target_link_libraries(paaas
    pico_stdlib
    tinyusb_device
    tinyusb_board
    pico_cyw43_arch_lwip_poll
)
pico_add_extra_outputs(paaas)
