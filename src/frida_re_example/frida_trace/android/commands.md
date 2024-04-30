# 常用命令举例

此处列出，Frida的frida-trace去hook安卓的app时，常用的具体命令：

```bash
frida-trace -U -n system_server --runtime=v8 -j '*ActivityManagerService!*'

frida-trace -U -n system_server --runtime=v8 -j '*handleProcessStartedLocked!*'

frida-trace -U -n system_server --runtime=v8 -j '*ActivityManager!*' -j '*!startProcessLocked' -j '*!handleProcessStartedLocked'

frida-trace -U -n system_server --runtime=v8 -j '*ActivityManager!*' -j '*!startProcessLocked' -j '*!handleProcessStartedLocked' -J '*!checkComponentPermission'

frida-trace -U -n system_server --runtime=v8 -j '*ActivityManager!*' -j '*!*startProcessLocked*' -j '*!*handleProcessStartedLocked*' -J '*!checkComponentPermission'

frida-trace -U -N com.wallpaper.hd.funny --runtime=v8 -j '*ActivityManager!*' -j '*!*startProcessLocked*' -j '*!*handleProcessStartedLocked*' -J '*!checkComponentPermission'

frida-trace -U -n system_server --runtime=v8 -j '*!startInstrumentation'

frida-trace -U -n system_server --runtime=v8 -j '*!bindService'
frida-trace -U -n system_server --runtime=v8 -j '*!bindService' -j '*!handleProcessStartedLocked'

frida-trace -U -n system_server --runtime=v8 -j '*!startService' -j '*!handleProcessStartedLocked' -j '*!forceStopPackage'

frida-trace -U -N com.wallpaper.hd.funny --runtime=v8 -j '*!execTransact' -j '*!onTransact'

frida-trace -U -N com.wallpaper.hd.funny -i 'onTransact'

frida-trace -U -i 'onTransact' -p 21925

frida-trace -U -N com.wallpaper.hd.funny -i '*onTransact*'

frida-trace -U -n system_server -i '*onTransact*'

frida-trace -U -n system_server --runtime=v8 -j '*!startService' -j '*!handleProcessStartedLocked' -j '*!forceStopPackage'  -J '*!checkComponentPermission' -i '*onTransact*'
```
