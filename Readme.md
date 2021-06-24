# 加密工具(Crypto)
> 本模块是对原生的`crypto`模块二次封装的，在使用上更加简单方便。


## 安装

```bash
npm install crypto.js
```


## 说明
> 本模块内置2种不同的引入方式。

```js
// 1、 传统的 commonJS引入, 所有的方法都在上面
var crypto = require('crypto.js')


// 2、 全新的 ESM 方式
import crypto from 'crypto.js'
import {
  uuid, 
  rand, 
  md5, 
  md5Sign, 
  sha1, 
  sha1Sign,
  sha256,
  sha256Sign,
  base64encode,
  base64decode,
} from 'crypto.js'

```



## 属性
> 其实就一个属性，即 `origin`，即为原生的`crypto`对象，方便在封装的方法中无法满足需求时，可以自行调用原生的`crypto`实现。

## 常用API方法
> 对使用频率非常高的几种加密/编码进行更加简便的封装。

### rand(len[, onlyNumber])
- len `<Number>`  需要的字符长度
- onlyNumber `<Boolean>` 返回纯数字字符串 [可选]

> 该方法用于生成指定长度的随机字符串`[a-z-A-z0-9]`

```javascript
let crypto = require('crypto.js')
crypto.rand(6) // ddjF7d
crypto.rand(16) // 4sf7dJH6tGHDjhdf
crypto.rand(6,  true) // 439875
crypto.rand(10, true) // 3458765234
```

### uuid()
> 返回一个如下格式的 xxxxxxxx-xxxx-xxxx-xxxxxxxx 的唯一ID
>> 1、加入机器码, 减小不同机器生成的uuid相同的机率
>> 2、每秒可生成20万个ID(测试机器: Intel i5-8500B@3.00GHz 16G内存)

```javascript
let crypto = require('crypto.js')
crypto.uuid() // 076d029f-4927-ec5f-5b06e35e

```



### md5(str[, encode])
- str `<Number>` | `<String>`
- encode `<String>` 可选

> 这方法，应该没有人不知道是做什么的了，`encode`是要返回的字符串编码，默认为`hex`， 可选`base64` 不过有这需求的人可能也许大概...很少吧。

```javascript
crypto.md5(123456) // e10adc3949ba59abbe56e057f20f883e
crypto.md5('123456') // e10adc3949ba59abbe56e057f20f883e
crypto.md5('hello world') // 5eb63bbbe01eeed093cb22bb8f5acdc3
crypto.md5('hello world', 'base64') // XrY7u+Ae7tCTyyK7j1rNww==
```


### md5Sign(file)
- file `<String>`

> 该方法用于计算文件的md5签名，`file`即为文件的路径。

```javascript
crypto.md5Sign('xx.jpg')
```


### sha1(str[, encode])
- str `<Number>` | `<String>`
- encode `<String>` 可选

> 这方法也应该没有人不知道是做什么的了，`encode`是要返回的字符串编码，默认为`hex`， 可选`base64` 不过有这需求的人可能也许大概...很少吧。

```javascript
crypto.sha1(123456) // 7c4a8d09ca3762af61e59520943dc26494f8941b
crypto.sha1('123456') // 7c4a8d09ca3762af61e59520943dc26494f8941b
crypto.sha1('hello world') // 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
crypto.sha1('hello world', 'base64') // Kq5sNclPz7QV2+lfQIuc6R7oRu0=
```


### sha1Sign(file)
- file `<String>`

> 该方法用于计算文件的sha1签名，`file`即为文件的路径。

```javascript
crypto.sha1Sign('xx.jpg')
```


### sha256(str[, encode])
- str `<Number>` | `<String>`
- encode `<String>` 可选

> 自然这方法，也没啥好说的了。


### sha256Sign(file)
- file `<String>`

> 都懂的。




### base64encode(str[, urlFriendly])
- str `<Number>` | `<String>` | `<Buffer>`
- urlFriendly `<Boolean>` 可选

> 这是用来进行base64编码的，本身没啥好说。主要是第2个参数，是指编码的结果是否对URL友好，默认为否; 如果为true，则会把+转成-，/转成_ (遵循RFC4648标准)。

```javascript
crypto.base64encode('hello world') //aGVsbG8gd29ybGQ=

```



### base64decode(str[, urlFriendly])
- str `<String>`
- urlFriendly `<Boolean>` 可选

> base64解码, 返回Buffer对象。同样`urlFriendly`是指要解码的字符串之前是否采用了URL友好处理，默认否。

```javascript
crypto.base64decode('aGVsbG8gd29ybGQ=')//  .toString('utf-8')  === hello world

```



## 更强大的API方法
> 除去上面8个更为常用的方法之外，还有很多很多也经常要到的，比如AES加密等，那此时就可以使用下面这里方法，自行配置了。

### 1. 散列算法
#### hash(mode, data[, outEncode])
- mode `<String>`
- data `<String>` | `<Buffer>`
- outEncode '<String>' 可选

> 散列算法(也称为哈希算法)，用来实现一些重要数据的模糊处理，以达到隐藏明文的目的。
> 上面的md5、sha1、sha256等，其实就是基于这个再次封装的结果;
> `mode`，即算法类型，常用的有 `md5, sha1, sha256, sha512`等;
> `data` 即为要加密的字符串;
> `outEncode`是输出的编码类型;

```javascript
crypto.hash('md5', '123456') //e10adc3949ba59abbe56e057f20f883e

```


### 2. HMAC算法
#### hmac(mode, data[, key][, outEncode])
- mode `<String>`
- data `<String>` | `<Buffer>`
- key `<String>` 可选
- outEncode '<String>' 可选

> HMAC算法，是在散列算法的基础上，与一个密钥结合在一起，以阻止对签名完整性的破坏。
> 与上面的散列算法相比，多了一个密钥的参数`key`;

```javascript
//a21cf00de4343af1b8b2087af07eb7b9
crypto.hmac('md5', '123456', 'sdfvkjfhd') 

```


### 3. 公钥加密
> 在上面的2种算法中，加密都是不可逆的，也就是说，加密后的字符，我们是没办法再还原回去了，但是有很多场景，需要我们对拿到的加密字符，还原到明文状态。
> 所以出现了公钥加密这种算法; 而`Node.js`本身给我们提供了4种与公钥加密相关的类：`Cipher/Decipher、Sign、Verify`，这里只讲前面2个，以及它们衍生出来的`Cipheriv/Decipheriv`;

#### cipher(mode, data[, key, inEncode, outEncode])
- mode `<String>`
- data `<String>` | `<Buffer>`
- key `<String>` 可选
- inEncode '<String>' 可选
- outEncode '<String>' 可选，默认base64

> `mode`为算法类型，常见的有`aes-128-cbc、aes-128-gcm`等等地，很多，具体有哪些可以通过 `this.crypto.getCiphers()` 来查看。
> 其他的参数与上面的HMAC算法相似; `inEncode`即声明要加密的数据是什么编码的，默认根据要加密的数据进行判断。
>> 需要注意的是, 算法类型为`aes-***-gcm`时, 返回的不是一个字符串, 而是一个对象{ enStr, authTag }, 解密时, 需要提供这个 authTag方可解密

```javascript
// 这里给出一个AES-128-CBC的加密例子

crypto.cipher('aes-128-cbc', '123456', 'abcdefg')
// mqA9ZPh9VV+fwKlfpicGVg==

crypto.cipher('aes-128-cbc', '123456', 'abcdefg', 'utf8', 'hex')
// 9aa03d64f87d555f9fc0a95fa6270656

// 要注意gcm算法的结果
crypto.cipher('aes-128-gcm', '123456', 'abcdefg')
// { enStr: 'qmo1a4Jz',
//   authTag: <Buffer c4 a0 3e ab e5 34 a0 ea 25 02 f0 91 06 f7 3b dd> 
// }

```



#### decipher(mode, data[, key, tag, inEncode, outEncode])
- mode `<String>`
- data `<String>` | `<Buffer>`
- key `<String>` 可选
- tag `<Buffer>` 可选(mode为gcm算法时必填)
- inEncode '<String>' 可选, 默认是base64
- outEncode '<String>' 可选，默认utf8

> 这是与上面的`cipher`对应的解密方法;

```javascript
// 这里不用指定编码，默认即为base64
crypto.decipher('aes-128-cbc', 'mqA9ZPh9VV+fwKlfpicGVg==', 'abcdefg')
// 123456

// 这里一定要指定，因为之前加密的时候，指定输出为hex，所以这里也要指定输入的是hex编码
crypto.decipher('aes-128-cbc', '9aa03d64f87d555f9fc0a95fa6270656', 'abcdefg', 'hex')
// 123456



// 要注意gcm算法的结果
// authTag: <Buffer c4 a0 3e ab e5 34 a0 ea 25 02 f0 91 06 f7 3b dd> 
crypto.decipher('aes-128-gcm', 'qmo1a4Jz', 'abcdefg', authTag)
// 123456


```


> 至于另外的`cipheriv/decipheriv`这2个方法，这里就不细讲了，和上面的这2个是同样的用法，只是要多1个参数`向量(iv)`
>> **`特别要注意的一点是，选择128位的加密算法，那key的长度就必须是16位，256则是32位，依此类推; 算法类型为gcm时,返回的是对象,解密时需要提供authTag `，具体的请看相关文档**