# lightsocks

## 编译
```
mkdir build
cd build
cmake ..
make -j16
```
## 运行
```
./ssserver -p 12111 -k V4kst1z -m rc4-md5
./sslocal -s 127.0.0.1 -p 12111 -l 9999 -k V4kst1z -m rc4-md5
```

## 支持的加密
* rc4-md5

## Todo
fix bugs
