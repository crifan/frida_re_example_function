# Android的JNI函数

用Frida去hook安卓的JNI函数：

* `RegisterNatives`
* `GetMethodID`
* `NewStringUTF`

的相关代码：

```js
class FridaUtil {
  ...

  static {
    ...
  }

  // constructor(curThrowableCls) {
  constructor() {
    console.log("FridaUtil constructor")
    // this.curThrowableCls = curThrowableCls
    // console.log("this.curThrowableCls=" + this.curThrowableCls)
  }

  // Frida pointer to UTF-8 string
  static ptrToUtf8Str(curPtr){
    var curUtf8Str = curPtr.readUtf8String()
    // console.log("curUtf8Str=" + curUtf8Str)
    return curUtf8Str
  }

  // Frida pointer to C string
  static ptrToCStr(curPtr){
    var curCStr = curPtr.readCString()
    // console.log("curCStr=" + curCStr)
    return curCStr
  }

  // get java class name
  // example:
  //  clazz=0x35 -> className=java.lang.ref.Reference
  //  clazz=0xa1 -> className=com.tencent.wcdb.database.SQLiteConnection
  //  clazz=0x91 -> className=java.lang.String
  static getJclassName(clazz){
    var env = Java.vm.tryGetEnv()
    // console.log("env=" + env) // env=[object Object]
    var className = env.getClassName(clazz)
    // console.log("className=" + className)
    return className
  }


  static findSymbolFromLib(soLibName, jniFuncName, callback_isFound) {
    console.log("soLibName=" + soLibName + ", jniFuncName=" + jniFuncName + ", callback_isFound=" + callback_isFound)
  
    var foundSymbolList = []
    let libSymbolList = Module.enumerateSymbolsSync(soLibName)
    // console.log("libSymbolList=" + libSymbolList)
    for (let i = 0; i < libSymbolList.length; i++) {
        var curSymbol = libSymbolList[i]
        // console.log("[" + i  + "] curSymbol=" + curSymbol)
  
        var symbolName = curSymbol.name
        // console.log("[" + i  + "] symbolName=" + symbolName)

        // var isFound = callback_isFound(symbolName)
        var isFound = callback_isFound(curSymbol, jniFuncName)
        // console.log("isFound=" + isFound)
  
        if (isFound) {
          var symbolAddr = curSymbol.address
          // console.log("symbolAddr=" + symbolAddr)

          foundSymbolList.push(curSymbol)
          console.log("+++ Found [" + i + "] symbol: addr=" + symbolAddr + ", name=" + symbolName)
        }
    }
  
    // console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static android_findFunction_libart_so(jniFuncName, func_isFound) {
    var foundSymbolList = FridaUtil.findSymbolFromLib("libart.so", jniFuncName, func_isFound)
    console.log("foundSymbolList=" + foundSymbolList)
    return foundSymbolList
  }

  static android_isFoundSymbol(curSymbol, symbolName){
    // return symbolName.includes("NewStringUTF")
    // return symbolName.includes("CheckJNI12NewStringUTF")
    // return symbol.name.includes("CheckJNI12NewStringUTF")

    // _ZN3art12_GLOBAL__N_18CheckJNI12NewStringUTFEP7_JNIEnvPKc.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKc
    // _ZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_
    // _ZNK3art12_GLOBAL__N_119NewStringUTFVisitorclENS_6ObjPtrINS_6mirror6ObjectEEEm
    // _ZN3art2gc4Heap16AllocLargeObjectILb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadEPNS_6ObjPtrINS5_5ClassEEEmRKT0_
    // _ZZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb0ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_ENKUlvE_clEv
    // _ZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKc
    // _ZZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // _ZZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
    // return symbol.name.includes("NewStringUTF")

    // symbolName.includes("RegisterNatives") && symbolName.includes("CheckJNI")
    // return symbolName.includes("CheckJNI15RegisterNatives")
    // return symbolName.includes("RegisterNatives")

    // _ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // _ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    // return symbol.name.includes("RegisterNatives")

    // return symbolName.includes("CheckJNI11GetMethodID")
    // return symbolName.includes("GetMethodID")

    // _ZN3art12_GLOBAL__N_18CheckJNI19GetMethodIDInternalEPKcP7_JNIEnvP7_jclassS3_S3_b
    // _ZN3art12_GLOBAL__N_18CheckJNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_.llvm.16005601603641821307
    // _ZN3art3JNIILb0EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // _ZN3art3JNIILb1EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
    // return symbol.name.includes("GetMethodID")

    return curSymbol.name.includes(symbolName)
  }

  static android_findJniFunc(jniFuncName){
    var jniSymbolList = FridaUtil.android_findFunction_libart_so(jniFuncName, FridaUtil.android_isFoundSymbol)
    return jniSymbolList
  }

  static android_doHookJniFunc_multipleMatch(foundSymbolList, callback_hookFunc){
    if (null == foundSymbolList){
      return
    }

    var symbolNum = foundSymbolList.length
    console.log("symbolNum=" + symbolNum)
    if (symbolNum == 0){
      return
    }

    for(var i = 0; i < symbolNum; ++i) {
      var eachSymbol = foundSymbolList[i]
      // console.log("eachSymbol=" + eachSymbol)
      var curSymbolAddr = eachSymbol.address
      console.log("curSymbolAddr=" + curSymbolAddr)

      Interceptor.attach(curSymbolAddr, {
        onEnter: function (args) {
          callback_hookFunc(eachSymbol, args)
        }
      })
    }
  
  }

  static android_hookJniFunc(jniFuncName, hookFunc){
    var jniSymbolList = FridaUtil.android_findJniFunc(jniFuncName)
    FridaUtil.android_doHookJniFunc_multipleMatch(jniSymbolList, hookFunc)
  }

}
```

注：

* `FridaUtil`的最新完整代码，详见：
  * https://github.com/crifan/JsFridaUtil/blob/main/frida/FridaUtil.js

调用=hook代码：

```js
function hookNative_NewStringUTF(){
  // var symbolList_NewStringUTF = find_NewStringUTF()
  // hoook_NewStringUTF(symbolList_NewStringUTF)

  FridaUtil.android_hookJniFunc("NewStringUTF", function(curSymbol, args){
    JsUtil.logStr("Trigged NewStringUTF [" + curSymbol.address + "]")
      // jstring NewStringUTF(JNIEnv *env, const char *bytes);
      var jniEnv = args[0]
      console.log("jniEnv=" + jniEnv)

      var newStrPtr = args[1]
      // var newStr = newStrPtr.readCString()
      // var newStr = FridaUtil.ptrToUtf8Str(newStrPtr)
      var newStr = FridaUtil.ptrToCStr(newStrPtr)
      console.log("newStrPtr=" + newStrPtr + " -> newStr=" + newStr)
  })
}

function hookNative_GetMethodID(){
  // var symbolList_GetMethodID = find_GetMethodID()
  // hoook_GetMethodID(symbolList_GetMethodID)

  FridaUtil.android_hookJniFunc("GetMethodID", function(curSymbol, args){
    JsUtil.logStr("Trigged GetMethodID [" + curSymbol.address + "]")
      // jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
      var jniEnv = args[0]
      console.log("jniEnv=" + jniEnv)

      var clazz = args[1]
      var jclassName = FridaUtil.getJclassName(clazz)
      console.log("clazz=" + clazz + " -> jclassName=" + jclassName)

      var namePtr = args[2]
      var nameStr = FridaUtil.ptrToUtf8Str(namePtr)
      console.log("namePtr=" + namePtr + " -> nameStr=" + nameStr)

      var sigPtr = args[3]
      var sigStr = FridaUtil.ptrToUtf8Str(sigPtr)
      console.log("sigPtr=" + sigPtr + " -> sigStr=" + sigStr)
  })
}

function hookNative_RegisterNatives(){
  // var symbolList_RegisterNatives = find_RegisterNatives()
  // hoook_RegisterNatives(symbolList_RegisterNatives)

  FridaUtil.android_hookJniFunc("RegisterNatives", function(curSymbol, args){
    JsUtil.logStr("Trigged RegisterNatives [" + curSymbol.address + "]")

    /*
      typedef struct {
        const char* name;
        const char* signature;
        void* fnPtr;
      } JNINativeMethod;

      jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
    */
    var jniEnv = args[0]
    console.log("jniEnv=" + jniEnv)

    var clazz = args[1]
    var jclassName = FridaUtil.getJclassName(clazz)
    console.log("clazz=" + clazz + " -> jclassName=" + jclassName)

    var methods = args[2]
    console.log("methods=" + methods)

    var nMethods = args[3]
    var methodNum = parseInt(nMethods)
    console.log("nMethods=" + nMethods + " -> methodNum=" + methodNum)
  })
}

function hookNative(){
  hookNative_RegisterNatives()
  hookNative_GetMethodID()
  hookNative_NewStringUTF()
}

function hookAndroid() {
  if(!Java.available){
    console.error("Java is not available")
    return
  }

  console.log("Java is available")
  console.log("Java.androidVersion=" + Java.androidVersion)

  Java.perform(function () {
    hookNative()

    console.log("-------------------- Begin Hook --------------------")
  })

}

setImmediate(hookAndroid)
```

输出：

* RegisterNatives

```bash
[8588] curSymbol=[object Object]
+++ Found smbol: addr=0x738cc36550, name=_ZN3art12_GLOBAL__N_18CheckJNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi.llvm.16005601603641821307
[9254] curSymbol=[object Object]
+++ Found smbol: addr=0x738ccb070c, name=_ZN3art3JNIILb0EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
[9761] curSymbol=[object Object]
+++ Found smbol: addr=0x738cd109f8, name=_ZN3art3JNIILb1EE15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
foundSymbolList=[object Object],[object Object],[object Object]
foundFuncPtr=[object Object],[object Object],[object Object]
symbolList_RegisterNatives.length=3
curAddr_RegisterNatives=0x738cc36550
curAddr_RegisterNatives=0x738ccb070c
curAddr_RegisterNatives=0x738cd109f8

-------------------- Trigged RegisterNatives [0x738cd109f8]--------------------
jniEnv=0xb4000074504b0b10
clazz=0x129
jclassName=android.net.NetworkUtils
methods=0x7375709008
nMethods=0xc
methodNum=12

-------------------- Trigged RegisterNatives [0x738cd109f8]--------------------
jniEnv=0x74504e88d0
clazz=0x45
jclassName=J.N
methods=0x72a0fa3b78
nMethods=0x3e
methodNum=62
-------------------- Trigged RegisterNatives [0x738cd109f8]--------------------
jniEnv=0x74504e88d0
clazz=0x49
jclassName=J.N
methods=0x72a0fa4148
nMethods=0x8f
methodNum=143
```

* GetMethodID

```bash
+++ Found [8067] symbol: addr=0x738cc40520, name=_ZN3art12_GLOBAL__N_18CheckJNI19GetMethodIDInternalEPKcP7_JNIEnvP7_jclassS3_S3_b
+++ Found [8406] symbol: addr=0x738cc2f90c, name=_ZN3art12_GLOBAL__N_18CheckJNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_.llvm.16005601603641821307
+++ Found [8879] symbol: addr=0x738cc6385c, name=_ZN3art3JNIILb0EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
+++ Found [9392] symbol: addr=0x738ccc3778, name=_ZN3art3JNIILb1EE11GetMethodIDEP7_JNIEnvP7_jclassPKcS7_
foundSymbolList=[object Object],[object Object],[object Object],[object Object]
symbolNum=4
curSymbolAddr=0x738cc40520
curSymbolAddr=0x738cc2f90c
curSymbolAddr=0x738cc6385c
curSymbolAddr=0x738ccc3778

-------------------- Trigged GetMethodID [0x738ccc3778] --------------------
jniEnv=0x74504ef410
clazz=0x45 -> jclassName=android.system.ErrnoException
namePtr=0x7382448900 -> nameStr=<init>
sigPtr=0x73824490b0 -> sigStr=(Ljava/lang/String;I)V

-------------------- Trigged GetMethodID [0x738ccc3778] --------------------
jniEnv=0x74504e8770
clazz=0xd -> jclassName=java.lang.Class
namePtr=0x72af707f32 -> nameStr=getDeclaredMethod
sigPtr=0x72af707f44 -> sigStr=(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

-------------------- Trigged GetMethodID [0x738ccc3778] --------------------
jniEnv=0x74504e5750
clazz=0x45 -> jclassName=android.system.ErrnoException
namePtr=0x7382448900 -> nameStr=<init>
sigPtr=0x73824490b0 -> sigStr=(Ljava/lang/String;I)V
```

* NewStringUTF

```bash
+++ Found [8540] symbol: addr=0x738cc337c8, name=_ZN3art12_GLOBAL__N_18CheckJNI12NewStringUTFEP7_JNIEnvPKc.llvm.16005601603641821307
+++ Found [9143] symbol: addr=0x738cc9b938, name=_ZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKc
+++ Found [9145] symbol: addr=0x738ccb64f0, name=_ZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_
+++ Found [9300] symbol: addr=0x738ccb7b6c, name=_ZNK3art12_GLOBAL__N_119NewStringUTFVisitorclENS_6ObjPtrINS_6mirror6ObjectEEEm
+++ Found [9301] symbol: addr=0x738ccb7750, name=_ZN3art2gc4Heap16AllocLargeObjectILb1ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadEPNS_6ObjPtrINS5_5ClassEEEmRKT0_
+++ Found [9302] symbol: addr=0x738ca308d8, name=_ZZN3art2gc4Heap24AllocObjectWithAllocatorILb1ELb0ENS_12_GLOBAL__N_119NewStringUTFVisitorEEEPNS_6mirror6ObjectEPNS_6ThreadENS_6ObjPtrINS5_5ClassEEEmNS0_13AllocatorTypeERKT1_ENKUlvE_clEv
+++ Found [9656] symbol: addr=0x738ccfbc24, name=_ZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKc
+++ Found [23806] symbol: addr=0x738d215948, name=_ZZN3art3JNIILb0EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
+++ Found [23812] symbol: addr=0x738d215950, name=_ZZN3art3JNIILb1EE12NewStringUTFEP7_JNIEnvPKcE19prev_bad_input_time
foundSymbolList=[object Object],[object Object],[object Object],[object Object],[object Object],[object Object],[object Object],[object Object],[object Object]
symbolNum=9
curSymbolAddr=0x738cc337c8
curSymbolAddr=0x738cc9b938
curSymbolAddr=0x738ccb64f0
curSymbolAddr=0x738ccb7b6c
curSymbolAddr=0x738ccb7750
curSymbolAddr=0x738ca308d8
curSymbolAddr=0x738ccfbc24
curSymbolAddr=0x738d215948
curSymbolAddr=0x738d215950

-------------------- Trigged NewStringUTF [0x738d215950] --------------------
jniEnv=0xb4000074504b0b10
newStrPtr=0x7ff3cc3650 -> newStr=false

-------------------- Trigged NewStringUTF [0x738d215950] --------------------
jniEnv=0xb4000074504b0b10
newStrPtr=0x7379c4c468 -> newStr=arm64-v8a

-------------------- Trigged NewStringUTF [0x738d215950] --------------------
jniEnv=0xb4000074504b0b10
newStrPtr=0x7379c4c5ac -> newStr=default:targetSdkVersion=30
```