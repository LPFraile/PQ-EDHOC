# Install script for directory: /home/panosalex/zephyr_v4.2.2/zephyr

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/home/panosalex/ncs/toolchains/911f4c5c26/opt/zephyr-sdk/arm-zephyr-eabi/bin/arm-zephyr-eabi-objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/arch/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/lib/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/soc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/boards/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/subsys/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/drivers/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/acpica/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/cmsis/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/cmsis-dsp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/cmsis-nn/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/cmsis_6/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/fatfs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/adi/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_afbr/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_ambiq/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/atmel/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_bouffalolab/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_espressif/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_ethos_u/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_gigadevice/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_infineon/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_intel/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/microchip/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_nordic/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/nuvoton/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_nxp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/openisa/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/quicklogic/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_renesas/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_rpi_pico/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_silabs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_st/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_stm32/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_tdk/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_telink/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/ti/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_wch/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hal_wurthelektronik/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/xtensa/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/hostap/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/liblc3/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/libmctp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/libmetal/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/littlefs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/loramac-node/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/lvgl/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/mbedtls/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/mcuboot/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/mipi-sys-t/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/nrf_wifi/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/open-amp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/openthread/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/percepio/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/picolibc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/segger/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/tinycrypt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/trusted-firmware-a/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/trusted-firmware-m/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/uoscore-uedhoc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/zcbor/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/modules/nrf_hw_models/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/kernel/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/cmake/flash/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/cmake/usage/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/cmake/reports/cmake_install.cmake")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/zephyr/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
