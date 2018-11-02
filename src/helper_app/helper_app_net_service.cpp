#include "helper_app_net_service.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <random>
#include <fstream>

#define PORT_NUM_FILENAME_PREFIX "PORT_NUM_"
#define MAX_TRIES_READ_WRITE 10

// reading network packets
bool common_read(int socket_fd, uint32_t* message_size, uint8_t** message) {
    if (::read(socket_fd, message_size, sizeof(uint32_t)) < 0) {
        std::cout << "Fail to execute read() for " << socket_fd << "!" << std::endl;
        return false;
    }

    *message = new uint8_t[*message_size];

    uint32_t total_bytes_read = 0;
    int tries = 0;
    
    while (tries++ < MAX_TRIES_READ_WRITE && total_bytes_read < *message_size) {
        uint32_t return_value = ::read(socket_fd, 
                *message + total_bytes_read, 
                *message_size - total_bytes_read);
        if (return_value < 0)  {
            std::cout << "Fail to execute read() for " << socket_fd << "! (part 2)" << std::endl;
            return false;
        }
        total_bytes_read += return_value;
    }
    
    if (total_bytes_read != *message_size) {
        std::cout << "read(): Fail to read all bytes! We have " << *message_size << " bytes, but only read "
            << total_bytes_read << " bytes." << std::endl;
        return false;
    }

    return true;
}

// reading network packets of fixed size
bool common_read_fixed(int socket_fd, uint32_t expected_message_size, uint8_t* message) {
    uint32_t actual_message_size;

    if (::read(socket_fd, &actual_message_size, sizeof(uint32_t)) < 0) {
        std::cout << "Fail to execute read_fixed() for " << socket_fd << "!" << std::endl;
        return false;
    }

    if (actual_message_size != expected_message_size) {
        std::cout << "read_fixed(): Expected " << expected_message_size << " bytes but received "
            << actual_message_size << " bytes." << std::endl;
        return false;
    }

    uint32_t total_bytes_read = 0;
    int tries = 0;

    while (tries++ < MAX_TRIES_READ_WRITE && total_bytes_read < expected_message_size) {
        uint32_t return_value = ::read(socket_fd, 
                message + total_bytes_read, 
                expected_message_size - total_bytes_read);
        if (return_value < 0)  {
            std::cout << "Fail to execute read_fixed() for " << socket_fd << "! (part 2)" << std::endl;
            return false;
        }
        total_bytes_read += return_value;
    }
    
    if (total_bytes_read != expected_message_size) {
        std::cout << "read_fixed(): Fail to read all bytes! We have " << expected_message_size
            << " bytes, but only read "
            << total_bytes_read << " bytes." << std::endl;
        return false;
    }

    return true;   
}

// writing network packets
bool common_write(int socket_fd, uint32_t message_size, uint8_t* message) {
    if (::send(socket_fd, &message_size, sizeof(uint32_t), 0) < 0) {
        std::cout << "Fail to execute write() for " << socket_fd << "!" << std::endl;
        return false;
    }

    uint32_t total_bytes_sent = 0;
    int tries = 0;

    while (tries++ < MAX_TRIES_READ_WRITE && total_bytes_sent < message_size) {
        uint32_t return_value = ::send(socket_fd, 
                message + total_bytes_sent, 
                message_size - total_bytes_sent, 0);
        if (return_value < 0)  {
            std::cout << "Fail to execute write() for " << socket_fd << "! (part 2)" << std::endl;
            return false;
        }
        total_bytes_sent += return_value;
    }

    if (total_bytes_sent != message_size) {
        std::cout << "write(): Fail to send all bytes! We have " << message_size << " bytes, but only sent "
            << total_bytes_sent << " bytes." << std::endl;
        return false;
    }

    return true;
}

// close a socket
bool common_close(int socket_fd) {
    if (::close(socket_fd) < 0) {
        std::cout << "close() for " << socket_fd << "failed!" << std::endl;
        return false;
    }

    return true;
}

hans_NetServer::hans_NetServer() {
    this->socket_fd = 0;
    this->socket_port = 0;
    this->socket_address = { 0 };
}

bool hans_NetServer::init_random_port(std::string name, int* final_port) {
    int rand = 8000 + (std::rand() % 40000);

    if (final_port != nullptr) {
        *final_port = rand;
    }

    return init_with_port(name, rand);
}

bool hans_NetServer::init_with_port(std::string name, int port) {
    server_name = name;
    socket_port = port;

    // open socket
    socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == 0) {
        std::cout << "Fail to open socket." << std::endl;
        return false;
    }

    // force reuse of address and port
    // use this in case we didn't properly close old ports
    int option = 1;
    if (::setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option)) != 0) {
        std::cout << "Fail to set option to reuse address and port." << std::endl;
        return false;
    }

    // bind socket to port
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr.s_addr = INADDR_ANY;
    socket_address.sin_port = ::htons(port);

    if (::bind(socket_fd, reinterpret_cast<sockaddr *>(&socket_address), 
            sizeof(socket_address)) < 0) {
        std::cout << "Fail to bind socket to port " << port << "." << std::endl;
        return false;
    }

    // write port number to file
    std::ofstream port_number_file(PORT_NUM_FILENAME_PREFIX + server_name);
    port_number_file << port << std::endl;
    port_number_file.close();

    return true;
}

bool hans_NetServer::start() {
    int max_backlog = 0;    // forbidding backlog usually gives consistent performance
                            // i.e. less likely to fail to accept()

    if (::listen(socket_fd, max_backlog) < 0) {
        std::cout << "Fail to listen for connection at " << socket_port << std::endl;
        return false;
    }

    return true;
}

int hans_NetServer::accept(struct sockaddr_in* conn_address) {
    sockaddr_in result;
    if (conn_address == nullptr) {
        conn_address = &result;
    }

    socklen_t conn_address_len = sizeof(sockaddr);

    int new_socket_fd = ::accept(socket_fd, reinterpret_cast<sockaddr *>(&conn_address), &conn_address_len);
    if (new_socket_fd < 0) {
        std::cout << "Fail to accept new connection." << std::endl;
    }

    return new_socket_fd;
}

bool hans_NetServer::read(int client_socket_fd, uint32_t* message_size, uint8_t** message) {
    return common_read(client_socket_fd, message_size, message);
}

bool hans_NetServer::read_fixed(int client_socket_fd, uint32_t expected_message_size, uint8_t* message) {
    return common_read_fixed(client_socket_fd, expected_message_size, message);
}

bool hans_NetServer::write(int client_socket_fd, uint32_t message_size, uint8_t* message) {
    return common_write(client_socket_fd, message_size, message);
}

bool hans_NetServer::close_client(int client_socket_fd) {
    return common_close(client_socket_fd);
}

bool hans_NetServer::close() {
    return common_close(socket_fd);
}

hans_NetClient::hans_NetClient() {
    this->socket_fd = 0;
    this->socket_port = 0;
    this->socket_address = { 0 };
}

bool hans_NetClient::init_from_port_number_file(std::string server_name, int* final_port) {
    int port = 0;

    std::ifstream port_number_file(PORT_NUM_FILENAME_PREFIX + server_name);
    if (!port_number_file.good()) {
        std::cout << "Fail to read file " 
            << PORT_NUM_FILENAME_PREFIX + server_name 
            << std::endl;
        return false;
    }

    port_number_file >> port;
    port_number_file.close();

    if (final_port != nullptr) {
        *final_port = port;
    }

    return init_with_port("127.0.0.1", port);
}

bool hans_NetClient::init_with_port(const char* address, int port) {
    socket_port = port;

    socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == 0) {
        std::cout << "Fail to open socket." << std::endl;
        return false;
    }

    socket_address.sin_family = AF_INET;
    socket_address.sin_port = ::htons(port);
    if (::inet_pton(socket_address.sin_family, address, &socket_address.sin_addr) <= 0) {
        std::cout << "Invalid address " << address << std::endl;
        return false;
    }

    return true;
}

bool hans_NetClient::connect() {
    if (::connect(socket_fd, reinterpret_cast<sockaddr*>(&socket_address), 
            sizeof(socket_address)) < 0) {
        std::cout << "Fail to connect to server at " << socket_port << ". Is server down?" << std::endl;
        return false;
    }

    return true;
}

bool hans_NetClient::read(uint32_t* message_size, uint8_t** message) {
    return common_read(socket_fd, message_size, message);
}

bool hans_NetClient::read_fixed(uint32_t expected_message_size, uint8_t* message) {
    return common_read_fixed(socket_fd, expected_message_size, message);
}

bool hans_NetClient::write(uint32_t message_size, uint8_t* message) {
    return common_write(socket_fd, message_size, message);
}

bool hans_NetClient::close() {
    return common_close(socket_fd);
}
