## welcome!
main分支是整合分支
其余分支以大家的名字来创建！

## 分支切换
![切换到main分支，main分支下的代码会出现](1700362143879.png)
![切换到个人分支，个人分支下的代码会出现](1700362191900.png)

## 上传代码
``` bash
git add [x可以是待上传的代码文件，或者是文件夹]
git commit -m "[提交的说明信息]"
git push 
```
举例，切换到main分支后，上传更新好的hello.md
``` bash
git add hello.md
git commit -m "read me first"
git push
```