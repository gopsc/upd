#!/bin/bash
# 检查是否提供了仓库名称参数
if [ $# -ne 1 ]; then
    echo "用法: $0 <仓库名称>"
    echo "示例: $0 mybot"
    exit 1
fi
REPO_NAME=$1
cd /bot
git clone https://gitcode.com/qingss0/${REPO_NAME} ${REPO_NAME}.gitcode
git clone https://github.com/gopsc/${REPO_NAME}
rm -rf ${REPO_NAME}.gitcode/.git
mv ${REPO_NAME}/.git  ${REPO_NAME}.gitcode/.git
cd ${REPO_NAME}.gitcode
git remote set-url origin git@github.com:gopsc/${REPO_NAME}.git
git add .giti*
git add *
git commit -m "^-^"
git push
cd ..
rm -rf ${REPO_NAME}
rm -rf ${REPO_NAME}.gitcode
