# Java通用

## describeJavaClass

```js
function describeJavaClass(className) {
  var jClass = Java.use(className);
  console.log(JSON.stringify({
    _name: className,
    _methods: Object.getOwnPropertyNames(jClass.__proto__).filter(m => {
    // _methods: Object.getOwnPropertyDescriptor(jClass.__proto__).filter(m => {
    // _methods: Object.getOwnPropertySymbols(jClass.__proto__).filter(m => {
      return !m.startsWith('$') // filter out Frida related special properties
         || m == 'class' || m == 'constructor' // optional
    }), 
    _fields: jClass.class.getFields().map(f => {
      return f.toString()
    })  
  }, null, 2))
}
```

## enumMethods

```js
// enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
  var hook = Java.use(targetClass);
  var ownMethods = hook.class.getDeclaredMethods();
  console.log("use getDeclaredMethods")

  // var ownMethods = hook.class.getMethods();
  // console.log("use getMethods")

  hook.$dispose;
  return ownMethods;
}
```

调用：

```js
  // enumerate all methods in a class
  var allMethods = enumMethods(javaClassName)
  allMethods.forEach(function(singleMethod) { 
    console.log(singleMethod)
  })
```

## enumProperties

```js
// enumerate all property=field declared in a Java class
function enumProperties(targetClass)
{
  var hook = Java.use(targetClass);
  // var ownMethods = hook.class.getFields();
  // console.log("use getFields")

  var ownFields = hook.class.getDeclaredFields();
  console.log("use getDeclaredFields")

  hook.$dispose;
  return ownFields;
}
```

调用：

```js
  var allProperties = enumProperties(javaClassName)
  allProperties.forEach(function(singleProperty) { 
    console.log(singleProperty)
  })
```

## printClassAllMethodsFields

```js
// print single java class all Functions=Methods and Fields=Properties
function printClassAllMethodsFields(javaClassName){
  console.log("==========" + "Class: " + javaClassName + " ==========")

  console.log("-----" + "All Properties" + "-----")
  var allProperties = enumProperties(javaClassName)
  allProperties.forEach(function(singleProperty) { 
    console.log(singleProperty)
  })

  console.log("-----" + "All Methods" + "-----")
  // enumerate all methods in a class
  var allMethods = enumMethods(javaClassName)
  allMethods.forEach(function(singleMethod) { 
    console.log(singleMethod)
  })
  console.log("")
}
```

### 举例

调用1：

```js
    var ContextImplClassName = "android.app.ContextImpl"
    printClassAllMethodsFields(ContextImplClassName)
```

调用2：

```js
  // var C660660PrrClassName = "X.C660660Prr"
  var C660660PrrClassName = "X.0Prr"
  printClassAllMethodsFields(C660660PrrClassName)
```

输出：

```bash
==========Class: X.0Prr ==========
-----All Properties-----
use getDeclaredFields
public static java.lang.String X.0Prr.LIZ
public static com.ss.android.common.AppContext X.0Prr.LIZIZ
public static java.lang.String X.0Prr.LIZJ
public static java.lang.String X.0Prr.LIZLLL
public static int X.0Prr.LJ
public static int X.0Prr.LJFF
public static java.lang.String X.0Prr.LJI
public static java.lang.String X.0Prr.LJII
public static java.util.concurrent.ConcurrentHashMap X.0Prr.LJIIIIZZ
public static boolean X.0Prr.LJIIIZ
public static volatile org.json.JSONObject X.0Prr.LJIIJ
public static java.lang.String X.0Prr.LJIIJJI
public static java.lang.String X.0Prr.LJIIL
public static java.lang.String X.0Prr.LJIILIIL
public static java.lang.String X.0Prr.LJIILJJIL
public static final java.lang.Object X.0Prr.LJIILL
public static X.0Pro X.0Prr.LJIILLIIL
public static X.0PsA X.0Prr.LJIIZILJ
public static boolean X.0Prr.LJIJ
public static java.lang.String X.0Prr.LJIJI
public static volatile com.ss.android.deviceregister.DeviceCategory X.0Prr.LJIJJ
public static java.lang.String X.0Prr.LJIJJLI
public static volatile boolean X.0Prr.LJIL
public static java.util.concurrent.ConcurrentHashMap X.0Prr.LJJ
-----All Methods-----
use getDeclaredMethods
public static android.content.pm.PackageInfo X.0Prr.LIZ(android.content.pm.PackageManager,java.lang.String,int)
public static java.lang.String X.0Prr.LIZ()
public static java.lang.String X.0Prr.LIZ(android.content.Context)
public static void X.0Prr.LIZ(int)
public static void X.0Prr.LIZ(X.0Pro)
public static void X.0Prr.LIZ(X.0PsA)
public static void X.0Prr.LIZ(android.content.Context,java.lang.String)
public static void X.0Prr.LIZ(com.ss.android.common.AppContext)
public static void X.0Prr.LIZ(com.ss.android.deviceregister.DeviceCategory)
public static void X.0Prr.LIZ(java.lang.String)
public static void X.0Prr.LIZ(java.lang.String,java.lang.Object)
public static void X.0Prr.LIZ(java.lang.String,java.lang.String)
public static void X.0Prr.LIZ(java.lang.Throwable)
public static void X.0Prr.LIZ(org.json.JSONObject)
public static void X.0Prr.LIZ(org.json.JSONObject,org.json.JSONObject)
public static void X.0Prr.LIZ(boolean)
public static boolean X.0Prr.LIZ(android.content.Context,org.json.JSONObject,boolean)
public static android.content.pm.ApplicationInfo X.0Prr.LIZIZ(android.content.pm.PackageManager,java.lang.String,int)
public static java.lang.String X.0Prr.LIZIZ()
public static java.lang.String X.0Prr.LIZIZ(android.content.Context)
public static void X.0Prr.LIZIZ(android.content.Context,java.lang.String)
public static void X.0Prr.LIZIZ(java.lang.String)
public static java.lang.String X.0Prr.LIZJ()
public static java.lang.String X.0Prr.LIZJ(android.content.Context)
public static void X.0Prr.LIZJ(java.lang.String)
public static int X.0Prr.LIZLLL()
public static void X.0Prr.LIZLLL(java.lang.String)
public static int X.0Prr.LJ()
public static void X.0Prr.LJ(java.lang.String)
public static java.lang.String X.0Prr.LJFF()
public static void X.0Prr.LJFF(java.lang.String)
public static java.lang.String X.0Prr.LJI()
public static boolean X.0Prr.LJII()
public static void X.0Prr.LJIIIIZZ()
```

## getStackStr

```js
// get current stack trace string
function getStackStr(ThrowableCls) {
  let newThrowable = ThrowableCls.$new()
  // console.log("getStackStr: newThrowable=" + newThrowable)
  var stackElements = newThrowable.getStackTrace()
  // console.log("getStackStr: stackElements=" + stackElements)
  var stackStr = "Stack: " + stackElements[0] //method//stackElements[0].getMethodName()
  for (var i = 1; i < stackElements.length; i++) {
    stackStr += "\n    at " + stackElements[i]
  }
  // stackStr = "\n\n" + stackStr
  stackStr = stackStr + "\n"
  // console.log("getStackStr: stackStr=" + stackStr)

  return stackStr
}
```

调用：

```js
  var stackStr = getStackStr(ThrowableCls)
  console.log(stackStr)
```

## PrintStack

```js
// 打印当前调用堆栈信息 print call stack
function PrintStack(ThrowableCls) {
  var stackStr = getStackStr(ThrowableCls)
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

## getFunctionCallStr

```js
// get Function call string
function getFunctionCallStr(funcName, funcParaDict){
  // var isAMSStartSevice = funcName === "AMS.startService"
  // if(isAMSStartSevice){
  //   console.log("getFunctionCallStr: funcName=" + funcName + ", funcParaDict=" + toJsonStr(funcParaDict))
  // }

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
  
  // if(isAMSStartSevice){
  //   console.log("getFunctionCallStr: logStr=" + logStr)
  // }

  return logStr
}
```

调用：

```js
  var functionCallStr = getFunctionCallStr(funcName, funcParaDict)
```

## printFunctionCallAndStack

```js
// print Function call and stack trace string
function printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls){
  // var isAMSStartSevice = funcName === "AMS.startService"
  // if (isAMSStartSevice){
  //   console.log("printFunctionCallAndStack: funcName=" + funcName + ", funcParaDict=" + toJsonStr(funcParaDict) + ", ThrowableCls=" + ThrowableCls)
  // }

  var functionCallStr = getFunctionCallStr(funcName, funcParaDict)

  // if (isAMSStartSevice){
  //   console.log("printFunctionCallAndStack: functionCallStr=" + functionCallStr)
  // }

  var stackStr = getStackStr(ThrowableCls)

  // if(isAMSStartSevice){
  //   console.log("printFunctionCallAndStack: stackStr=" + stackStr)
  // }

  var functionCallAndStackStr = `${functionCallStr}\n${stackStr}`
  // var functionCallAndStackStr = functionCallStr + "\n" + stackStr

  // if(isAMSStartSevice){
  //   console.log("printFunctionCallAndStack: functionCallAndStackStr=" + functionCallAndStackStr)
  // }

  // return functionCallAndStackStr
  console.log(functionCallAndStackStr)
}
```

调用：

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

## findClass

```js
// find loaded classes that match a pattern (async)
// for 抖音：会崩溃 Process terminated
function findClass(pattern)
{
  console.log("Finding all classes that match pattern: " + pattern + "\n");


  Java.enumerateLoadedClasses({
    onMatch: function(aClass) {
      if (aClass.match(pattern)){
        console.log(aClass)
      }
    },
    onComplete: function() {}
  });
}
```

## printAllClasses

```js
// emulate print all Java Classes
// for 抖音：会崩溃 Process terminated
function printAllClasses(){
  // findClass("*")
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      console.log(className);
    },
    onComplete: function() {}
  });
}
```
