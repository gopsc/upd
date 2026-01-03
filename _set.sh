#!/bin/bash
cd "$(dirname "$0")" || exit
python3 -m venv .env
#sudo chmod +x .env/bin/activate
source .env/bin/activate
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
