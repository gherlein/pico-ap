cmake_minimum_required(VERSION 3.13)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(pico_sdk_import.cmake)

project(main C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(PICO_BOARD pico_w)

pico_sdk_init()

add_executable(main    
    main.c
    dhcpserver/dhcpserver.c
    dnsserver/dnsserver.c
)

pico_enable_stdio_usb(main 0)
pico_enable_stdio_uart(main 1)

target_include_directories(main PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        ${CMAKE_CURRENT_LIST_DIR}/dhcpserver
        ${CMAKE_CURRENT_LIST_DIR}/dnsserver
)

pico_add_extra_outputs(main)

target_link_libraries(main
	pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background 
    #pico_cyw43_arch_none
    # other libs as needed
)

add_custom_target(flash
    COMMAND /bin/bash ../flash main.elf
    DEPENDS main
)
add_custom_target(reset
    COMMAND /bin/bash ../reset
    DEPENDS main
)

