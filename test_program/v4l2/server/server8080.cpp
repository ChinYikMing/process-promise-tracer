/**
 * Video for Linux version 2 (V4L2) example 5 - video capture
 *
 * Based on
 * - https://linuxtv.org/downloads/v4l-dvb-apis/uapi/v4l/capture.c.html
 *
 * Kyle M. Douglass, 2018
 * kyle.m.douglass@gmail.com
 */

#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>

using namespace cv;
using namespace std;

int main(int argc, char *argv[]) {

    int port = 8080;
    sockaddr_in servAddr;
    bzero((char*)&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);
 
    int serverSd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSd < 0) {
        cerr << "Error establishing the server socket" << endl;
        exit(0);
    }
    int bindStatus = bind(serverSd, (struct sockaddr*) &servAddr, sizeof(servAddr));
    if(bindStatus < 0) {
        cerr << "Error binding socket to local address" << endl;
        exit(0);
    }
    cout << "Waiting for a client to connect..." << endl;
    listen(serverSd, 5);
    sockaddr_in newSockAddr;
    socklen_t newSockAddrSize = sizeof(newSockAddr);
    int newSd = accept(serverSd, (sockaddr *)&newSockAddr, &newSockAddrSize);
    if(newSd < 0) {
        cerr << "Error accepting request from client!" << endl;
        exit(1);
    }
    cout << "Connected with client!" << endl;
    int bytesRead, bytesWritten = 0;

    Mat image;
    VideoWriter outputVideo("byclient.avi", VideoWriter::fourcc('M', 'J', 'P', 'G'), 25.0, Size(640, 480));

    while(1) {
        recv(newSd, (Mat*)&image, sizeof(image), 0);
        outputVideo.write(image);
    }
    
    close(newSd);
    close(serverSd);
    cout << "Connection closed..." << endl;
    
    return 0;
}
