set(eapp_bin attestor-badram)
set(eapp_src eapp/attestor.c)
set(host_bin attestor-runner-badram)
set(host_src host/attestor-runner.cpp host/host.cpp)
set(verifier_bin verifier-badram)
set(verifier_src remote-verifier/verifier.cpp)
set(package_name "attestor-badram.ke")
set(eyrie_plugins "none")


if(NOT DEFINED fw_bin)
   set(fw_bin ../../../images/fw_dynamic.bin)
endif()
get_filename_component(fw_file ${fw_bin} NAME)
set(package_script "./attestor-runner-badram attestor-badram eyrie-rt loader.bin --sm-bin ${fw_file}")

set(READ_ALIAS_INC "$ENV{READ_ALIAS_INC}")

if (NOT READ_ALIAS_INC STREQUAL "")
  message(STATUS "Using READ_ALIAS_INC=${READ_ALIAS_INC}")
  include_directories(AFTER "${READ_ALIAS_INC}")
else()
  message(STATUS "READ_ALIAS_INC not set; external read_alias headers will not be available")
endif()

set(READ_ALIAS_SRC "$ENV{READ_ALIAS_SRC}")

if (READ_ALIAS_SRC STREQUAL "")
  message(STATUS "READ_ALIAS_SRC not set; readalias.c will not be compiled into ${host_bin}")
else()
  message(STATUS "Using READ_ALIAS_SRC=${READ_ALIAS_SRC}")
endif()


# eapp

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} "-nostdlib -static" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})
target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${READ_ALIAS_INC}
)

# host

add_executable(${host_bin} ${host_src} ${READ_ALIAS_SRC})
target_link_libraries(${host_bin}
  ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER})
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
  )
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/common
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${KEYSTONE_SDK_DIR}/include/verifier
  PUBLIC ${READ_ALIAS_INC}
)


# verifier
add_executable(${verifier_bin} ${verifier_src})

target_link_libraries(${verifier_bin}
 ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER}
)

set_target_properties(${verifier_bin}
  PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO OUTPUT_NAME "verifier.bin"
)
target_include_directories(${verifier_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/common
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/verifier)

if(NOT DEFINED fw_bin)
  message(AUTHOR_WARNING "fw_bin should be defined by upper CMake files/ build system. Setting to default")
  set(fw_bin ../../../images/fw_dynamic.bin)
endif()

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt loader.bin)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add sm binary -- TODO: fix, should come from upper levels
if(NOT DEFINED fw_bin)
  message(AUTHOR_WARNING "fw_bin should be defined by upper CMake files/ build system. Setting to default")
  set(fw_bin ../../../images/fw_dynamic.bin)
endif()

get_filename_component(fw_file ${fw_bin} NAME)
set(package_script "./attestor-runner-badram attestor-badram eyrie-rt loader.bin --sm-bin ${fw_file}")

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin} ${fw_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package  ${verifier_bin})
