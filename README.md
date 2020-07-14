# libleak

`libleak` detects memory leak by hooking memory functions (e.g. `malloc`)
by LD_PRELOAD.

There is no need to modify or re-compile the target program, and you can
enable/disable the detection during target running.

In fact `libleak` can not identify memory leak, while it just takes the
memory as leak if it lives longer than a threshold. The threshold is 60
second by default, but you should set it according to your scenarios.

There is less impact on performance, compared with `valgrind` and `memleax`.

It prints the full call-stack at suspicious memory leak point, and easier
to use, compared with other similar libraries (e.g. `mtrace`).

# LICENCE

GPLv2

# OS-MACHINE

- GNU/Linux only by now. But FreeBSD should be OK with some code changing

- x86_64 is only tested by now. But others should be OK.


# BUILD FROM SOURCE

    $ git clone --recursive https://github.com/WuBingzheng/libleak.git
    $ cd libleak
    $ make

# USAGE

### basic

1. [Download](https://github.com/WuBingzheng/libleak/releases) or build the shared-object `libleak.so`.

2. change the permission: $ chmod a+x libleak.so

3. touch the output file: $ touch ./a.out

4. Run the target program:

        $ LD_PRELOAD=/path/of/libleak.so ./a.out

5. Then you will read output in `/tmp/libleak.$pid` in time.

### set expire threshold

As said above, you should set expire threshold according to your scenarios.

For example, if you are debugging an HTTP server with keepalive, and there are
connections last for more than 5 minutes, you should set the threshold to 300
second to cover it.
If your program is expected to free every memory in 1 second, you should set
the threshold to 2 to get report in time.

The threshold is set by environment variable `LEAK_EXPIRE` (in second, default is 60):

    $ LD_PRELOAD=/path/of/libleak.so LEAK_EXPIRE=300 ./a.out

Besides, the threshold will be increased if any memory block is freed after
expiration, with `LEAK_AUTO_EXPIRE` enabled (default is disabled):

    $ LD_PRELOAD=/path/of/libleak.so LEAK_AUTO_EXPIRE=1 ./a.out

### enable/disable detection during running

`libleak` begins the detection at the very beginning of target process running
by default. However you can enable/disable the detection during running by
setting `LEAK_PID_CHECK` and `LEAK_PID_FILE`:

    $ LD_PRELOAD=/path/of/libleak.so LEAK_PID_CHECK=10 ./a.out

`LEAK_PID_CHECK` set the interval (in second, default is 0) to check `LEAK_PID_FILE`.

`LEAK_PID_FILE` (default is `/tmp/libleak.enabled`) contains target pids:
one pid each line, no empty line, no comment line.
You can add or delete pids to/from this file during running.

To enable detecting process pid=1234:

    $ echo 1234 >> /tmp/libleak.enabled

To disable detecting process pid=1234:

    $ sed -i '/1234/d' /tmp/libleak.enabled

### disable shared libraries calling

If your program uses a shared library that allocates too much memory
which ruins the log file, AND you can make sure that there is no leak in
calling it, `LEAK_LIB_BLACKLIST` can be used to disable it.
Library name can be got from `ldd $your-program`.
If there are more than one libraries, use `,` to seperate them:

    $ LD_PRELOAD=/path/of/libleak.so LEAK_LIB_BLACKLIST=libmysqlclient.so.20.3.8,librdkafka.so.1 ./a.out

### skip initial phase

Programs always allocate some memory in initial phase and do not free them.
`LEAK_AFTER` can be used to skip this. If it's set, `libleak`
starts to detect after this time (in second):

    $ LD_PRELOAD=/path/of/libleak.so LEAK_AFTER=1 ./a.out

### for multi-thread program

`libleak` is multi-thread safe.

### for multi-process program

Log file will be created for each process.

Besides you can choose which processes to be detect by `LEAK_PID_FILE`
and `LEAK_PID_CHECK` said above.

### set the log

The log file is set by `LEAK_LOG_FILE` (default is `/tmp/libleak.$pid`).

There is also a statistics report when disabled or target normal termination,
either via exit(3) or via return from the main().


# READ LOG

After the program running, you can check the output log (e.g. by `tail -f /tmp/libleak.$pid`).

The memory blocks that live longer than the threshold will be printed as:

    callstack[1] expires. count=1 size=1024/1024 alloc=1 free=0
        0x00007fd322bd8220  libleak.so  /path/libleak/libleak.c:674  malloc()
        0x000000000040084e  test  /path/test/test.c:30  foo()
        0x0000000000400875  test  /path/test/test.c:60  bar()
        0x0000000000400acb  test  /path/test/test.c:67  main()

`callstack[1]` is the ID of callstack where memory leak happens.

The backtrace is showed only on the first time, while it only prints
the ID and counters if expiring again:

    callstack[1] expires. count=2 size=1024/2048 alloc=2 free=0

If the expired memory block is freed later, it prints:

    callstack[1] frees after expired. live=6 expired=1 free_expired=1

Stop the output when you think there is enough log.
You can stop the output by terminating the target process,
or by by `LEAK_PID_FILE` and `LEAK_PID_CHECK` temporarily.

After stopping, statistics is printed for the CallStacks with memory leak:

    # callstack statistics: (in ascending order)

    callstack[1]: may-leak=1 (1024 bytes)
        expired=2 (2048 bytes), free_expired=1 (1024 bytes)
        alloc=12 (12288 bytes), free=10 (10240 bytes)
        freed memory live time: min=1 max=5 average=4
        un-freed memory live time: max=13
    callstack[4]: may-leak=4 (32 bytes)
        expired=4 (32 bytes), free_expired=0 (0 bytes)
        alloc=4 (32 bytes), free=0 (0 bytes)
        freed memory live time: min=0 max=0 average=0
        un-freed memory live time: max=7

The statistics are straight:

  - `may-leak`, equal to `expired - free_expired`,
  - `expired`, count of memory blocks that live longer than threshold,
  - `free_expired`, count of memory blocks that freed after expiration,
  - `alloc`, total count of allocation,
  - `free`, total count of free.

The `may-leak` may be the most important one. All callstacks are sorted by this in ascending order.
So you should check all callstacks backward.

If a free is totally missed in your program, you should only check the callstacks with `free=0` .
Otherwise, if memory leak only happens in some cases, you need to check all callstacks.

When you find some suspicious callstack, go back to find its full backtrace by the ID, and check you code.

`libleak` just try to give some help, while some inspiration is still need to find the memory leak finally.

If memory pool is used in your program (e.g. `Nginx`), you must try harder to locate the memory leak.

Good luck!
