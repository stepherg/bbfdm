# Parallel UBUS calls

All `operate` operation and `get` operation with a depth up to 'BBFDM_SUBPROCESS_DEPTH(2)'
runs in a parallel subprocess to avoid blocking the next call.

```console
root@iopsys:~# time ubus call bbfdm get '{"path":"Device."}' >/dev/null &
root@iopsys:~# time ubus call bbfdm get '{"path":"Device.Users."}' >/dev/null
real    0m 0.07s
user    0m 0.00s
sys     0m 0.00s
root@iopsys:~#
real     0m 1.86s
user    0m 0.05s
sys     0m 0.00s

[1]+  Done                       time ubus call bbfdm get "{\"path\":\"Device.\"}" >/dev/null
root@iopsys:~#
```

