# native C

## hookNativeFunc

```js
function hookNativeFunc(){
  // /Users/crifan/dev/dev_src/androidReverse/Android/android.googlesource.com/base-refs_heads_main/core/jni/android_util_Binder.cpp
  // status_t onTransact( uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags = 0) override {
  // var foundOnTransact = Module.findExportByName(null, "onTransact")

  // let transactModuleName = "libBinder.so"
  // let transactModuleName = "libbinder.so"
  let transactModuleName = "libbinder_ndk.so"

  var foundOnTransact = Module.findExportByName(transactModuleName, "onTransact")

  console.log("foundOnTransact=" + foundOnTransact)
  if (foundOnTransact) {
    Interceptor.attach(foundOnTransact, {
      onEnter: function(args) {
        var code = args[0]
        var data = args[1]
        var reply = args[2]
        var flags = args[3]
        console.log("onTransact: code=" + code + ", data=" + data + ", reply=" + reply + ", flags=" + flags)
      },
      onLeave: function(retVal) {
        console.log("onTransact: retval=" + retVal)
      }
    })
  }

  // var foundTransact = Module.findExportByName(null, "transact")
  var foundTransact = Module.findExportByName(transactModuleName, "transact")
  console.log("foundTransact=" + foundTransact)
}
```

调用：

```js
function hookForceStop() {
  if(!Java.available){
    console.error("Java is not available")
    return
  }
  console.log("Java is available")
  console.log("Java.androidVersion=" + Java.androidVersion)
  Java.perform(function () {
    ...
    hookNativeFunc()
    ...
  }
}

setImmediate(hookForceStop)
```
