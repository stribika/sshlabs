#!/usr/bin/python3 -O

import argparse
from copy import copy
from multiprocessing import cpu_count
import os
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Generate SSH moduli file")
parser.add_argument("-a", "--cpu-affinity",
    action="store_true", help="force ssh-keygen processes to run on distinct cores")
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
        self.queue = []
        self.threads = threads
        self.processes = [ None ] * self.threads

    def submit(self, callback, *args):
        self.queue.append(( args, callback ))
        try:
            self.__start(self.processes.index(None))
        except ValueError:
            pass

    def wait(self):
        while self.queue or self.processes != [ None ] * self.threads:
            for i in range(len(self.processes)):
                if self.processes[i] != None:
                    ( process, callback ) = self.processes[i]
                    try: process.wait(timeout=1)
                    except subprocess.TimeoutExpired: continue
                    try: callback(process)
                    except: print("oops, something went wrong", file=sys.stderr)
                self.__start(i)

    def __start(self, n):
        if self.queue:
            task = self.queue.pop(0)
            ( command, callback ) = task
            if args.cpu_affinity:
                core = hex(1 << n)[2:]
                command = ( "taskset", core ) + command
            self.processes[n] = ( subprocess.Popen(command), callback )
        else:
            self.processes[n] = None

    def shutdown(self):
        for p in self.processes:
            if p != None: p[0].terminate()
        self.processes = [ None ] * self.threads
        self.queue = []

class Context(object): pass

pool = Pool(args.threads)
output = open(args.output, "w")

def generate(context):
    context.all_temp = tempfile.mkstemp(prefix="all." + str(context.size) + ".")
    pool.submit(
        lambda p: test(context, p),
#        "touch", context.all_temp[1]
        "ssh-keygen", "-G", context.all_temp[1], "-b", str(context.size)
    )

def test(context, process):
    if process.returncode != 0:
        print(
            "generator process failed, there will be no",
            context.size,
            "bit moduli in the output",
            file=sys.stderr
        )
        return
    chunk_temps = []
    for i in range(args.threads):
        chunk_temp = tempfile.mkstemp(prefix="chunk.{}.{}.".format(context.size, i))
        chunk_temp = ( open(chunk_temp[0], "w"), chunk_temp[1] )
        chunk_temps.append(chunk_temp)
    try:
        with open(context.all_temp[0], "r") as all_file:
            while True:
                line = None
                for chunk_temp in chunk_temps:
                    line = all_file.readline()
                    if line: print(line, file=chunk_temp[0])
                    else: break
                if not line: break
        os.unlink(context.all_temp[1])
    finally:
        for chunk_temp in chunk_temps: chunk_temp[0].close()
    for i in range(args.threads):
        ctx = copy(context)
        ctx.chunk_id = i
        ctx.chunk_temp = chunk_temps[i]
        ctx.safe_temp = tempfile.mkstemp(prefix="safe.{}.{}.".format(ctx.size, ctx.chunk_id))
        pool.submit(
            (lambda c: lambda p: gather(c, p))(ctx), # fucking wat
#            "touch", ctx.safe_temp[1]
            "ssh-keygen", "-T", ctx.safe_temp[1], "-f", ctx.chunk_temp[1]
        )

def gather(context, process):
    if process.returncode != 0:
        print(
            "tester process",
            context.chunk_id,
            "for",
            context.size,
            "bit moduli failed",
            file=sys.stderr
        )
        return
    with open(context.safe_temp[0], "r") as safe_file:
        output.write(safe_file.read())
    os.unlink(context.chunk_temp[1])
    os.unlink(context.safe_temp[1])

try:
    for size in range(args.min_size, args.max_size + 1024, 1024):
        context = Context()
        context.size = size
        generate(context)
    pool.wait()
except:
    print("fatal error")
    pool.shutdown()
finally:
    output.close()

