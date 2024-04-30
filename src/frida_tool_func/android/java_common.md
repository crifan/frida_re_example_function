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

调用：

```js
    var ContextImplClassName = "android.app.ContextImpl"
    printClassAllMethodsFields(ContextImplClassName)
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
function findClass(pattern)
{
	console.log("Finding all classes that match pattern: " + pattern + "\n");

	Java.enumerateLoadedClasses({
		onMatch: function(aClass) {
			if (aClass.match(pattern))
				console.log(aClass)
		},
		onComplete: function() {}
	});
}
```
