#include "helper_app/helper_app_net_service.h"
#include <iostream>

int main(int argc, char** argv) {
    int port;

    hans_NetClient client;
    client.init_from_port_number_file("server", &port);
    
    if (!client.connect()) {
        std::cout << "Fail to connect to " << port << "!" << std::endl;
        return 1;
    }

    std::cout << "Connected to " << port << std::endl;

    uint8_t message[] = { 'H', 'i', '\0' };
    client.write(sizeof(message), message);
    std::cout << "Sent: " << message << std::endl;

    uint8_t* received;
    uint32_t received_bytes;
    client.read(&received_bytes, &received);
    std::cout << "Read: " << received << " (" << received_bytes << " bytes)" << std::endl;

    client.close();
}
