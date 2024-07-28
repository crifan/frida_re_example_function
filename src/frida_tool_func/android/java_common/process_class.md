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
