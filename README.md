[TOC]

# depick

制作 `Docker` 镜像时，使用 `depick` 可以分析依赖，并将依赖复制到指定目录。

# Usage

```bash
depick <root> <path|file> ..
```
|Args|Description|
|-|-|
|`root`|根目录|
|`path`|需要复的可行文件|
|`file`|与 `path` 不同，`file` 中不包含 `/` 时，会搜索 `PATH`|

# Example

```bash
depick /usr/bin/ls /usr/bin/bash
depick ls bash
```