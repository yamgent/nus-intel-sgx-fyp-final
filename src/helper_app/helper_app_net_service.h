#ifndef HELPER_APP_NET_SERVICE_H
#define HELPER_APP_NET_SERVICE_H

#include <netinet/in.h>
#include <string>

class hans_NetServer {
private:
    int socket_fd;
    int socket_port;
    struct sockaddr_in socket_address;
    
    std::string server_name;

public:
    hans_NetServer();

    bool init_random_port(std::string name, int* final_port);
    bool init_with_port(std::string name, int port);
    bool start();

    int accept(struct sockaddr_in* conn_address);
    bool read(int client_socket_fd, uint32_t* message_size, uint8_t** message);
    bool read_fixed(int client_socket_fd, uint32_t expected_message_size, uint8_t* message);
    bool write(int client_socket_fd, uint32_t message_size, uint8_t* message);
    bool close_client(int client_socket_fd);

    bool close();
};

class hans_NetClient {
private:
    int socket_fd;
    int socket_port;
    struct sockaddr_in socket_address;

public:
    hans_NetClient();

    bool init_from_port_number_file(std::string server_name, int* final_port);
    bool init_with_port(const char* address, int port);

    bool connect();

    bool read(uint32_t* message_size, uint8_t** message);
    bool read_fixed(uint32_t expected_message_size, uint8_t* message);
    bool write(uint32_t message_size, uint8_t* message);

    bool close();
};

#endif
