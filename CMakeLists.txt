set(NEARLINK_ROLE "server")

if("${NEARLINK_ROLE}" STREQUAL "server")
    set(SOURCES "${SOURCES}"
        "${CMAKE_CURRENT_SOURCE_DIR}/nearlink_server.c"
        PARENT_SCOPE)
elseif("${NEARLINK_ROLE}" STREQUAL "client")
    set(SOURCES "${SOURCES}"
        "${CMAKE_CURRENT_SOURCE_DIR}/nearlink_client.c"
        PARENT_SCOPE)
else()
    message(FATAL_ERROR
        "Invalid NEARLINK_ROLE='${NEARLINK_ROLE}'.")
endif()

set(PUBLIC_HEADER "${PUBLIC_HEADER}" "${CMAKE_CURRENT_SOURCE_DIR}" PARENT_SCOPE)
