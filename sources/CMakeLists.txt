set(TFHE_PREFIX /path/to/tfhe)
set(APP_NAME tches)
set(SOME_NAME tches)
set(MAIN1 ${CMAKE_CURRENT_LIST_DIR}/main.cpp)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(APP_SRCS
  ${CMAKE_CURRENT_LIST_DIR}/main.cpp
  ${CMAKE_CURRENT_LIST_DIR}/algos.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tables.cpp
  ${CMAKE_CURRENT_LIST_DIR}/instr.cpp
  ${CMAKE_CURRENT_LIST_DIR}/instr_16.cpp
  ${CMAKE_CURRENT_LIST_DIR}/instri.cpp
  ${CMAKE_CURRENT_LIST_DIR}/bootstrapping.cpp
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitch.cpp
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitchkey.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tlwe-functions-extra.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tlwekeyswitch.cpp
  )

set(APP_HEADERS
  ${CMAKE_CURRENT_LIST_DIR}/tables.h
  ${CMAKE_CURRENT_LIST_DIR}/algos.h
  ${CMAKE_CURRENT_LIST_DIR}/instr.h
  ${CMAKE_CURRENT_LIST_DIR}/instri.h
  ${CMAKE_CURRENT_LIST_DIR}/instr_16.h
  ${CMAKE_CURRENT_LIST_DIR}/bootstrapping.h
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitch.h
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitchkey.h
  ${CMAKE_CURRENT_LIST_DIR}/tlwe-functions-extra.h
  ${CMAKE_CURRENT_LIST_DIR}/tlwekeyswitch.h

  )





add_executable(${APP_NAME} ${APP_SRCS} ${MAIN1} ${APP_HEADERS})

include_directories(${TFHE_PREFIX}/src/include)

get_filename_component(TFHE_LIB_DIR "${TFHE_PREFIX}/build/libtfhe" ABSOLUTE)
 target_link_libraries(${APP_NAME} "${TFHE_LIB_DIR}/libtfhe-spqlios-avx.so") 



set_target_properties(${APP_NAME}
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  )
