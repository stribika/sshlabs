#!/usr/bin/python3 -O

import argparse
from multiprocessing import cpu_count
import os
import subprocess
import tempfile

parser = argparse.ArgumentParser(description="Generate SSH moduli file")
parser.add_argument("-s", "--min-size",
    type=int, default=2048, metavar="BITS",  help="minimum moduli size in bits")
parser.add_argument("-S", "--max-size",
    type=int, default=8192, metavar="BITS", help="maximum moduli size in bits")
parser.add_argument("-t", "--threads",
    type=int, default=cpu_count(), help="how many parallel threads to use")
parser.add_argument("-o", "--output",
    metavar="FILE", help="output file")
args = parser.parse_args()

class Pool(object):
    def __init__(self, threads):
        self.threads = threads
        self.queue = []
        self.processes = []

    def submit(self, callback, *args):
        self.queue.append(( args, callback ))
        self.__start()

    def wait(self):
        while self.processes or self.queue:
            self.__start()
            for process, callback in self.processes:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    continue
                callback(process)
            self.processes = [ p for p in self.processes if p[0].returncode == None ]

    def __start(self):
        while self.queue and len(self.processes) < self.threads:
            task = self.queue.pop(0)
            self.processes.append(( subprocess.Popen(task[0]), task[1] ))

pool = Pool(args.threads)
output = open(args.output, "w")

def generate(size):
    print("generate", size)
    all_temp = tempfile.mkstemp(prefix="all." + str(size) + ".")
    pool.submit(
        lambda p: test(all_temp, p),
        "ssh-keygen", "-G", all_temp[1], "-b", str(size)
    )

def test(all_temp, process):
    print("test", all_temp, process.args)
    if process.returncode:
        print("generator process failed", file=sys.stderr)
        return
    chunk_temps = []
    for i in range(args.threads):
        chunk_temp = tempfile.mkstemp(prefix="chunk." + str(i) + ".")
        chunk_temp = ( open(chunk_temp[0], "w"), chunk_temp[1] )
        chunk_temps.append(chunk_temp)
    try:
        with open(all_temp[0], "r") as all_file:
            while True:
                line = None
                for chunk_temp in chunk_temps:
                    line = all_file.readline()
                    if line: print(line, file=chunk_temp[0])
                    else: break
                if not line: break
        os.unlink(all_temp[1])
    finally:
        for chunk_temp in chunk_temps: chunk_temp[0].close()
    for i in range(args.threads):
        safe_temp = tempfile.mkstemp(prefix="safe." + str(i) + ".")
        pool.submit(
            (lambda s: lambda p: gather(s, p))(safe_temp), # fucking wat
            "ssh-keygen", "-T", safe_temp[1], "-f", chunk_temp[1]
        )

def gather(safe_temp, process):
    print("gather", safe_temp, process.args)
    if process.returncode:
        print("tester process failed", file=sys.stderr)
        return
    with open(safe_temp[0], "r") as safe_file:
        output.write(safe_file.read())
    os.unlink(safe_temp[1])

for size in range(args.min_size, args.max_size + 1024, 1024):
    generate(size)
pool.wait()
output.close()
