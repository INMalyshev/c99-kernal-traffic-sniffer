#ifndef C99_KERNAL_TRAFFIC_SNIFFER 
#define C99_KERNAL_TRAFFIC_SNIFFER

#define LOCKFILE "/var/run/analizer.pid"

#define SNAPSHOW_BUFFER_LENGTH 128
#define SECOND_GRANULARITY 1

enum command_type {
    COMMAND_TYPE_UNDEFINED = 0,

    HIDE_MODULE = 1,
    UNHIDE_MODULE = 2,

    START_ANALIZER = 3,
    STOP_ANALIZER = 4,

    SET_OUTPUT_TYPE = 5,
};

enum output_type {
    SHOW_MODE_UNDEFINED = 0,

    MODULE_STATS = 1,
    TRAFFIC_SNAPSHOT = 2,
};

struct management_package
{
    enum command_type command;
    enum output_type output;
};

struct traffic_snapshot {
    uint64_t timestamp;
    uint32_t ip_v4_addr;
    uint64_t traffic_length;
    uint64_t traffic_size;
};

struct module_stats {
    uint64_t time_start;
    uint8_t is_analizer_running;
    uint8_t is_buffer_overloaded;
    enum output_type output;
};


#endif //C99_KERNAL_TRAFFIC_SNIFFER