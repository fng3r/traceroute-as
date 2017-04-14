import socket
from concurrent.futures import ThreadPoolExecutor
import timeit
import time


def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        _ = sock.connect((host, port))
    except socket.timeout:
        return
    except Exception as exc:
        return\
            # print(port, exc)
    finally:
        sock.close()
    return port


def portscan(workers):
    host = 'localhost'
    ports = range(1, 8192)
    pool = ThreadPoolExecutor(max_workers=workers)
    res = list(filter(lambda x: x, pool.map(scan_port, ports)))
    print(res)


def other_performance_test(workers):
    start = time.clock()
    partition = [2048, 4096, 6044, 8192]
    ranges = [range(i * 2048, partition[i]) for i in range(len(partition))]
    for ports in ranges:
        pool = ThreadPoolExecutor(max_workers=workers)
        pool.map(scan_port, ports)

    end = time.clock()
    print('workers per pool - %s' % workers, end-start)


def performance_test():
    workers_amounts = [1024, 2048, 4096]
    for workers in workers_amounts:
        start = time.clock()
        ports = range(1, 16384)
        pool = ThreadPoolExecutor(max_workers=workers)
        list(filter(lambda x: x, pool.map(scan_port, ports)))
        end = time.clock()
        print(workers, end-start)

if __name__ == '__main__':
    host = 'localhost'
    partition = []
    print('One thread pool:')
    performance_test()
    # print('4 thread pools:')
    # workers = [64, 128, 256, 512]
    workers = [1]
    for w in workers:
        other_performance_test(w)