# js小的代码段

## 判断元素是否在列表数组中

* 概述
	```js
	array.includes(item, fromIndex)
	string.includes(substring, fromIndex)
	```
* 详解

### 数组列表

举例：

```js
const array = [1, 2, 3];
const value = 1;
const isInArray = array.includes(value);
console.log(isInArray); // true
```

#### 特殊情况

此处传入的`obj1`，其实是个`object`

但是数值对比：

```js
console.log("typeof obj1=" +  (typeof obj1))
// typeof obj1=object
if(obj1 == 1903654775) {
```

也是返回true的

所以之前误以为用：

```js
let ApkUtilReadJsonKeyList = [-262969152, 1903654773, 1114793335, 1896449818, 1903654775 ]

if(ApkUtilReadJsonKeyList.includes(obj1)) {
```

是可行的。结果实际不行。

实际要改为：

把`obj1`的`object`，转换成`Number`：

```js
let ApkUtilReadJsonKeyList = [-262969152, 1903654773, 1114793335, 1896449818, 1903654775 ]
var objInt = Number(obj1)

// if(obj1 == 1903654775) {
// if(obj1 in ApkUtilReadJsonKeyList) {
// if(ApkUtilReadJsonKeyList.includes(obj1)) {
if(ApkUtilReadJsonKeyList.includes(objInt)) {
	// 1903654775 == 0x71777777
	isPrintStack = true
	console.log("typeof obj1=" +  (typeof obj1))
	console.log("typeof objInt=" +  (typeof objInt))
	console.log("objInt=" + objInt)
	console.log("found HashMap.put for ApkUtilReadJsonKeyList")
```

才可以

```bash
typeof obj1=object
typeof objInt=number
objInt=1903654775
found HashMap.put for ApkUtilReadJsonKeyList
```

### 字符串

判断主字符串是否包含子字符串：

* 概述：用`str`的`includes`
	```js
	mainString.includes(subString)
	```
* 详解

测试代码：

```js
  var mainStr = "Stack: X.0Pru.LIZ(Native Method)"
  var subStr = "X.0Pru.LIZ"
  var isMatch = mainStr.includes(subStr)
  console.log("isMatch=" + isMatch)
```

输出：

```bash
isMatch=true
```

## 判断字符串是否在dict的key中

* 判断key是否在字典dict中
	```js
	curKey in someDict
	```

举例：

```js
let cfgPrintOnceStackExceptionDict = {
    // key: arg list(arg0, arg1, ...)
    "+[NSURLRequest requestWithURL:]": [],
    "+[WAURLQueryItem queryItemWithName:value:]": ["ENC", undefined],
}

var iOSObjCallStr = "+[WAURLQueryItem queryItemWithName:value:]"
var isMatch = iOSObjCallStr in cfgPrintOnceStackExceptionDict
console.log("isMatch=" + isMatch)
```

输出：`isMatch=true`

## 获取列表的子列表

```js
var argList = [0, 1, 2, 3, 4]
var subArgList = argList.slice(2)
console.log("argList=" + argList + " -> subArgList=" + subArgList)
```

输出：

```bash
argList=0,1,2,3,4 -> subArgList=2,3,4
```

## 函数默认参数

定义=写法 举例：

```js
function printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, filterList=undefined){
...
  if (filterList != undefined) {
    ...
  }
...
}
```

调用：

* 不传递（带默认参数值的）最后一个参数
	```js
	printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls)
	```
* 传递（带默认参数值的）最后一个参数
	```js
	printFunctionCallAndStack(funcName, funcParaDict, ThrowableCls, ["X.0Pru.LIZ"])
	```
