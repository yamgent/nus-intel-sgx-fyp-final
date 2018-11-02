#include "helper_app/helper_app_net_service.h"
#include <iostream>

#include <cstdlib>
#include <ctime>

int main(int argc, char** argv) {
    std::srand(std::time(nullptr));

    int port;

    hans_NetServer server;
    server.init_random_port("server", &port);
    server.start();

    std::cout << "Actively listen to connection " << port << "..." << std::endl;

    int client_socket_fd = server.accept(nullptr);
    if (client_socket_fd < 0) {
        int error_number = errno;
        std::cout << "Connection failed! Return code: ";

        switch (error_number) {
            default:
                std::cout << error_number;
                break;
            case EINVAL:
                std::cout << "EINVAL";
                break;
        }

        std::cout << std::endl;
        return 1;
    }

    std::cout << "Accept connection!" << std::endl;

    uint8_t* received;
    uint32_t received_bytes;
    server.read(client_socket_fd, &received_bytes, &received);
    std::cout << "Read: " << received << " (" << received_bytes << " bytes)" << std::endl;

    uint8_t message[] = { 'B', 'a', 'c', 'k', '\0' };
    server.write(client_socket_fd, sizeof(message), message);
    std::cout << "Sent: " << message << std::endl;

    server.close_client(client_socket_fd);
    server.close();

    return 0;
}
