# 单个类的单个函数

举例：想要hook[前面](../single_class/README.md)的类`X.0Pru`的函数：

## 普通函数 = 不带重载的函数

直接去hook：

```js
  // public void run() {
  // public void X.0Pru.run()
  var X0PruFuncRun = X0PruCls.run
  // var X0PruFuncRun = X0PruCls.run()
  console.log("X0PruFuncRun=" + X0PruFuncRun)
  if (X0PruFuncRun) {
    X0PruFuncRun.implementation = function () {
      // add what you want
      return this.run()
    }
  }
```

### 加上：打印函数调用堆栈

如果想要，hook的函数触发时，打印函数调用堆栈，可以用：

```js
  // public void run() {
  // public void X.0Pru.run()
  var X0PruFuncRun = X0PruCls.run
  // var X0PruFuncRun = X0PruCls.run()
  console.log("X0PruFuncRun=" + X0PruFuncRun)
  if (X0PruFuncRun) {
    X0PruFuncRun.implementation = function () {
      var funcName = "X.0Pru.run"
      var funcParaDict = {}
      printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

      return this.run()
    }
  }
```

* 说明
  * 关于工具类函数`printFunctionCallAndStack`的源码
    * 详见：[函数调用堆栈](../../../../frida_tool_func/android/java_common/call_stack.md)

* 输出举例

```bash
X.0Pru.run:
Stack: X.0Pru.run(Native Method)
    at kotlin.jvm.internal.ALambdaS640S0100000_23.invoke$35(SourceFile:33882174)
    at kotlin.jvm.internal.ALambdaS640S0100000_23.invoke(Unknown Source:74)
    at com.ss.android.ugc.bytex.pthread.base.convergence.core.ThreadWorker.run(Unknown Source:101)
    at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1137)
    at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:637)
    at com.ss.android.ugc.bytex.pthread.base.convergence.core.ExemptThreadFactory$newThread$t$1.run(Unknown Source:39)
    at java.lang.Thread.run(Thread.java:1012)
```

### 带重载的函数

需要用`overload`指定对应对应是具体哪个函数：

* `public final void LIZ()`

```js
  // /* JADX WARN: Type inference failed for: r0v20, types: [X.0PmX] */
  // public final void LIZ() {
  // public final void X.0Pru.LIZ()
  // var X0PruFuncLIZ_0 = X0PruCls.LIZ
  // var X0PruFuncLIZ_0 = X0PruCls.LIZ.overload('java.lang.String', 'org.json.JSONObject')
  var X0PruFuncLIZ_0 = X0PruCls.LIZ.overload()
  console.log("X0PruFuncLIZ_0=" + X0PruFuncLIZ_0)
  if (X0PruFuncLIZ_0) {
    X0PruFuncLIZ_0.implementation = function () {
      return this.LIZ()
    }
  }
```

* `private boolean LIZ(JSONObject jSONObject)`

```js
  // private boolean LIZ(JSONObject jSONObject) {
  // private boolean X.0Pru.LIZ(org.json.JSONObject)
  var X0PruFuncLIZ_1 = X0PruCls.LIZ.overload('org.json.JSONObject')
  console.log("X0PruFuncLIZ_1=" + X0PruFuncLIZ_1)
  if (X0PruFuncLIZ_1) {
    X0PruFuncLIZ_1.implementation = function (jSONObject) {
      return this.LIZ(jSONObject)
    }
  }
```

* `private boolean LIZ(String str, JSONObject jSONObject)`

```js
  // private boolean X.0Pru.LIZ(java.lang.String,org.json.JSONObject)
  // private boolean LIZ(String str, JSONObject jSONObject) {
  var X0PruFuncLIZ_2 = X0PruCls.LIZ.overload('java.lang.String', 'org.json.JSONObject')
  console.log("X0PruFuncLIZ_2=" + X0PruFuncLIZ_2)
  if (X0PruFuncLIZ_2) {
    X0PruFuncLIZ_2.implementation = function (str, jSONObject) {
      return this.LIZ(str, jSONObject)
    }
  }
```
