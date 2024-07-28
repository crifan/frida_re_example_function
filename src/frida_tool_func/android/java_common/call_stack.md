# Java函数调用堆栈

## genStackStr

```js
// generate current stack trace string
function genStackStr(ThrowableCls) {
  let newThrowable = ThrowableCls.$new()
  // console.log("genStackStr: newThrowable=" + newThrowable)
  var stackElements = newThrowable.getStackTrace()
  // console.log("genStackStr: stackElements=" + stackElements)
  var stackStr = "Stack: " + stackElements[0] //method//stackElements[0].getMethodName()
  for (var i = 1; i < stackElements.length; i++) {
    stackStr += "\n    at " + stackElements[i]
  }
  // stackStr = "\n\n" + stackStr
  stackStr = stackStr + "\n"
  // console.log("genStackStr: stackStr=" + stackStr)

  return stackStr
}
```

调用：

```js
  var stackStr = genStackStr(ThrowableCls)
  console.log(stackStr)
```

## PrintStack

```js
// 打印当前调用堆栈信息 print call stack
function PrintStack(ThrowableCls) {
  var stackStr = genStackStr(ThrowableCls)
  console.log(stackStr)

  // let newThrowable = ThrowableCls.$new()
  // let curLog = Java.use("android.util.Log")
  // let stackStr = curLog.getStackTraceString(newThrowable)
  // console.log("stackStr=" + stackStr)
}
```

调用：

```js
    var ThrowableCls = Java.use("java.lang.Throwable")
    console.log("ThrowableCls=" + ThrowableCls)

    PrintStack(ThrowableCls)
```

## genFunctionCallStr

```js
// generate Function call string
function genFunctionCallStr(funcName, funcParaDict){
  var logStr = `${funcName}:`
  // var logStr = funcName + ":"
  var isFirst = true

  for(var curParaName in funcParaDict){
    let curParaValue = funcParaDict[curParaName]
    var prevStr = ""
    if (isFirst){
      prevStr = " "
      isFirst = false
    } else {
      prevStr = ", "
    }

    logStr = `${logStr}${prevStr}${curParaName}=` + curParaValue
    // logStr = logStr + prevStr + curParaName + "=" + curParaValue
  }

  return logStr
}
```

调用：

```js
  var functionCallStr = genFunctionCallStr(funcName, funcParaDict)
```

## printFunctionCallAndStack

```js
// print Function call and stack trace string
function printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=undefined){
  // console.log("filterList=" + filterList)

  var needPrint = true

  var functionCallStr = genFunctionCallStr(funcName, funcParaDict)

  var stackStr = genStackStr(ThrowableCls)

  if (filterList != undefined) {
    needPrint = false

    for (const curFilter of filterList) {
      // console.log("curFilter=" + curFilter)
      if (stackStr.includes(curFilter)) {
        needPrint = true
        // console.log("needPrint=" + needPrint)
        break
      }
    }
  }

  if (needPrint) {
    var functionCallAndStackStr = `${functionCallStr}\n${stackStr}`
    // var functionCallAndStackStr = functionCallStr + "\n" + stackStr
  
    // return functionCallAndStackStr
    console.log(functionCallAndStackStr)  
  }
}
```

调用：

* 场景1：不传递filter，没过滤条件，直接全都打印

```js
    // ---------------------------------------- android.app.ContextImpl
    var ContextImplClassName = "android.app.ContextImpl"
    var ContextImplCls = Java.use(ContextImplClassName)
    console.log("ContextImplCls=" + ContextImplCls)
    // printClassAllMethodsFields(ContextImplClassName)

    // public boolean bindServiceAsUser(Intent service, ServiceConnection conn, int flags, UserHandle user)
    var bindServiceAsUserFunc4 = ContextImplCls.bindServiceAsUser.overload('android.content.Intent', 'android.content.ServiceConnection', 'int', 'android.os.UserHandle')
    if (bindServiceAsUserFunc4) {
      bindServiceAsUserFunc4.implementation = function (service, conn, flags, user) {
        // console.log("ContextImpl.bindServiceAsUser 4: service=" + service + ", conn=" + conn + ", flags=" + flags + ", user=" + user)
        // PrintStack(ThrowableCls)
        var funcName = "ContextImpl.bindServiceAsUser 4"
        var funcParaDict = {
          "service": service,
          "conn": conn,
          "flags": flags,
          "user": user,
        }
        printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)

        return this.bindServiceAsUser(service, conn, flags, user)
      }
    }
```

* 场景2：传递filter，只有堆栈中出现filter的字符串，才打印

```js
      var funcName = "GlobalProxyLancet.com_ss_android_ugc_aweme_lancet_MemoryOptLancet_toString"
      var funcParaDict = {
        "jSONObject": jSONObject
      }
      // printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)
      // printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=["X.0Pru.LIZ"])
      printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, ["X.0Pru.LIZ"])
```
