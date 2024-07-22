# 安卓hook的demo示例

此处给出，普通的，用Frida去hook安卓的某个app时候的，js脚本的demo示例：

* hook_androidApp.js

```js
/**
 * Update: 20240721
 * Usage:
 *  frida -U -f your.app.package -l hook_androidApp.js
*/

/*******************************************************************************
 * Const & Config
*******************************************************************************/

/*******************************************************************************
 * Common Util
*******************************************************************************/

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

/*******************************************************************************
 * Main Hook
*******************************************************************************/

function hookSomeApp() {
  var SomeClassName = "xxx.yyy.zzz"
  printClassAllMethodsFields(SomeClassName)

  var SomeCls = Java.use(SomeClassName)
  console.log("SomeCls=" + SomeCls)

  // then do what you want
}

function hookAndroid() {
  if(!Java.available){
    console.error("Java is not available")
    return
  }

  console.log("Java is available")
  console.log("Java.androidVersion=" + Java.androidVersion)

  Java.perform(function () {
    hookSomeApp()
  })
}

setImmediate(hookAndroid)
```

调用：

```bash
frida -U -f your.app.package -l hook_androidApp.js
```
