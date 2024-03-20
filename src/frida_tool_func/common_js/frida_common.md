# Frida的js通用函数

## objcArgsToArgArray

```js
/* Convert args to real Javascript Array

    Note: 
        Interceptor.attach onEnter(args), args is not real JS array -> later operation will fail
            args.slice(2)
            Array.from(args)
        -> so need here to conver to real Array, then all is OK
*/
function objcArgsToArgArray(args, realArgCount){
    var argsArr = Array()
    // console.log("initial: argsArr=" + argsArr)
    argsArr.push(args[0])
    argsArr.push(args[1])
    // console.log("add frist two: argsArr=" + argsArr)

    for (let curArgIdx = 0; curArgIdx < realArgCount; curArgIdx++) {
        const curArg = args[curArgIdx + 2]
        argsArr.push(curArg)
    }
    // console.log("add all args: argsArr=" + argsArr)
    return argsArr
}
```

用法举例：

```js
Interceptor.attach(curMethod.implementation, {
  onEnter: function(args) {
    const realArgCount = occurrences(funcName, ":")
    console.log("realArgCount: " + realArgCount)

    args = objcArgsToArgArray(args, realArgCount)
```

效果：

```js
// 后续针对js的Array的args去操作，就不会报错了
var realArgList = args.slice(2)
```

详见：

* 【已解决】iOS逆向WhatsApp：Frida的js的函数堆栈打印优化：支持特定函数的特定参数值时打印
* 【已解决】Frida中js去获取Interceptor.attach的onEnter的args时报错：RangeError invalid array index

## isValidPointer：判断指针是否有效

* 背景：
  * 正常的指针值：
    * `0x194d20320`
    * `0x103e79420`
    * `0x2831ac880`
  * 异常的一些指针指：
    * 0x0
    * 0xc

代码：

```js
// check pointer is valid or not
// example
// 		0x103e79560 => true
// 		0xc => false
function isValidPointer(curPtr){
	let MinValidPointer = 0x10000
	var isValid = curPtr > MinValidPointer
	return isValid
}
```

用法举例：

```js
console.log(isValidPointer(0xc))
```

输出：

```bash
false
```
