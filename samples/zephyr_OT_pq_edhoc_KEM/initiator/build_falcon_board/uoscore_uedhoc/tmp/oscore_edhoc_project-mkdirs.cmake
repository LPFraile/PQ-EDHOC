# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/../../..")
  file(MAKE_DIRECTORY "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/../../..")
endif()
file(MAKE_DIRECTORY
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/../../.."
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc"
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/tmp"
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/src/oscore_edhoc_project-stamp"
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/src"
  "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/src/oscore_edhoc_project-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/src/oscore_edhoc_project-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/panosalex/zephyr_v4.2.2/PQ-EDHOC/samples/zephyr_OT_pq_edhoc_KEM/initiator/build_falcon_board/uoscore_uedhoc/src/oscore_edhoc_project-stamp${cfgdir}") # cfgdir has leading slash
endif()
