# ZeroMQ

ZeroMQ, aka ZMQ, is essentially a sockets framework. It makes it easy to build
messaging topologies across different types of sockets. They also are language
agnostic by way of having driver implementations in every language: Scheme, 
Java, C, Ruby, Haskell, Erlang; and Brubeck uses the Python driver.

It is common for service oriented architectures to be constructed with HTTP
interfaces, but Brubeck believes ZMQ is a more suitable tool. It provides
multiple message distribution patterns and lets you open multiple types of
sockets. 


## Simple Examples

Here is a simple job distributor. It passes messages round-robin to any
connected hosts.

    import zmq
    import time

    ctx = zmq.Context()
    s = ctx.socket(zmq.PUSH)
    s.bind("ipc://hellostream:5678")

    while True:
        s.send("hello")
        print 'Sending a hello'
        time.sleep(1)

This what a simple consumer could look like. See what happens if you hook up
multiple consumers.

    import zmq
    import datetime

    ctx = zmq.Context()
    s = ctx.socket(zmq.PULL)
    s.connect("ipc://hellostream:5678")
    
    while True:
        msg = s.recv()
        print 'Received:', msg
        

# Brubeck and ZMQ