import Queue
import functools
import socket

import errno

import sys
from tornado import ioloop
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPClient


def handle_response(response):
    if response.error:
        print "Error:", response.error
    else:
        print "body:", response.body


def handle_connection(connection, address):
    print ">>>1 connection,", connection, address

# def connection_up(sock, fd, events):
#     #print fd, sock, events
#     try:
#         connection, address = sock.accept()
#     except socket.error, e:
#         if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
#             raise
#         return
#     connection.setblocking(0)
#     handle_connection(connection, address)
#     fd_map[connection.fileno()] = connection
#     connection_handler = functools.partial(client_handler, address)
#     io_loop.add_handler(connection.fileno(), connection_handler, io_loop.READ)
#     print ">>>connection_up: new switch", connection.fileno(), connection_handler
#     message_queue_map[connection] = Queue.Queue()

def new_sock(block):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(block)
    return sock

if __name__ == "__main__":
    http_client = AsyncHTTPClient()
    sync_client = HTTPClient()
    body = """<eventSubscribe cookie="1487028371/fc4fe3b1-546f-42b2-9cf5-3ed28de45462"> </eventSubscribe> """
    request = HTTPRequest(url="http://172.16.86.149/nuova", method="POST", body=body,
                          auth_username="ucspe", auth_password="ucspe")

    http_client.fetch(request, handle_response)
    print "send subscribe"

    io_loop = ioloop.IOLoop.instance()
    sock = new_sock(0)
    sock.connect(("172.16.86.147", 80))
    #response = sync_client.fetch(request)
    #print response.body

    io_loop.add_handler(sock.fileno(), handle_response, io_loop.READ)
    try:
        io_loop.start()
    except KeyboardInterrupt:
        io_loop.stop()
        print ">>>quit"

        sys.exit(0)