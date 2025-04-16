#include "accless.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 4096;

int main() {
    // Create a TCP socket.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Allow reuse of the address.
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Bind the socket to the port.
    sockaddr_in address;
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for connections.
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    std::cout << "HTTP server listening on port " << PORT << std::endl;

    while (true) {
        // Accept a new connection.
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char buffer[BUFFER_SIZE];
        std::memset(buffer, 0, sizeof(buffer));
        int bytesRead = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytesRead < 0) {
            perror("read");
            close(client_fd);
            continue;
        }
        buffer[bytesRead] = '\0';

        // Simple check: if the request starts with "GET", proceed.
        if (std::strncmp(buffer, "GET", 3) == 0) {
            std::string output;
            if (accless::checkChain("word-count", "splitter", 1)) {
                output = "accless: access approved :-)\n";
            } else {
                output = "accless: access denied :-(\n";
            }

            std::ostringstream response;
            response << "HTTP/1.1 200 OK\r\n"
                     << "Content-Length: " << output.size() << "\r\n"
                     << "Content-Type: text/plain\r\n"
                     << "\r\n"
                     << output;
            std::string responseStr = response.str();
            write(client_fd, responseStr.c_str(), responseStr.size());
        } else {
            std::string badResponse = "HTTP/1.1 400 Bad Request\r\n\r\nOnly GET supported.";
            write(client_fd, badResponse.c_str(), badResponse.size());
        }
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
