# Java的类的处理

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


## getJavaClassName

```js
  static getJavaClassName(curObj){
    var javaClsName = null
    if (null != curObj) {
      // javaClsName = curObj.constructor.name
      javaClsName = curObj.$className
      // console.log("javaClsName=" + javaClsName)
      // var objType = (typeof curObj)
      // console.log("objType=" + objType)
    }
    // console.log("javaClsName=" + javaClsName)
    return javaClsName
  }
```

## isJavaClass

```js
  static isJavaClass(curObj, expectedClassName){
    var clsName = FridaAndroidUtil.getJavaClassName(curObj)
    // console.log("clsName=" + clsName)
    var isCls = clsName === expectedClassName
    // console.log("isCls=" + isCls)
    return isCls
  }
```

## castToJavaClass

```js
  // cast current object to destination class instance
  static castToJavaClass(curObj, toClassName){
    if(curObj){
      // // for debug
      // var objClsName  =FridaAndroidUtil.getJavaClassName(curObj)
      // console.log("objClsName=" + objClsName)

      const toClass = Java.use(toClassName)
      // console.log("toClass=" + toClass)
      var toClassObj = Java.cast(curObj, toClass)
      // console.log("toClassObj=" + toClassObj)
      return toClassObj
    } else{
      return null
    }
  }
```
