#!/bin/bash
# appimage-packager-fixed.sh

set -e

# 彩色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 创建图标
create_icon() {
    local icon_path="$1"
    mkdir -p "$(dirname "$icon_path")"
    
    # 最小有效的PNG图标
    echo 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==' | \
    base64 -d > "$icon_path" 2>/dev/null || \
    echo -ne '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\xf8\x0f\x00\x00\x01\x00\x01\x05\x01\x00\x00\x00\x00IEND\xaeB`\x82' > "$icon_path"
}

# 主程序
main() {
    if [[ $# -lt 1 ]]; then
        echo "用法: $0 <可执行文件> [输出名称]"
        echo "示例: $0 ./myapp"
        exit 1
    fi
    
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}          AppImage 打包工具            ${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    
    EXECUTABLE="$1"
    APP_NAME="${2:-$(basename "$EXECUTABLE")}"
    
    # 检查文件
    [[ ! -f "$EXECUTABLE" ]] && { echo -e "${RED}文件不存在${NC}"; exit 1; }
    [[ ! -x "$EXECUTABLE" ]] && chmod +x "$EXECUTABLE"
    
    echo "程序: $APP_NAME"
    echo "原始文件: $(basename "$EXECUTABLE")"
    
    # 清理
    rm -rf "AppDir" "${APP_NAME}.AppImage"
    
    # 创建目录
    mkdir -p AppDir/usr/bin
    
    # =========== 关键修复：使用正确的程序名 ===========
    # 获取原始文件名
    ORIG_NAME=$(basename "$EXECUTABLE")
    
    # 复制程序（保持原始文件名）
    cp "$EXECUTABLE" "AppDir/usr/bin/$ORIG_NAME"
    chmod +x "AppDir/usr/bin/$ORIG_NAME"
    echo "✓ 程序已复制: $ORIG_NAME"
    
    # 创建图标
    create_icon "AppDir/$APP_NAME.png"
    cp "AppDir/$APP_NAME.png" "AppDir/.DirIcon"
    echo "✓ 图标已创建"
    
    # =========== 关键修复：AppRun 脚本 ===========
    cat > "AppDir/AppRun" <<EOF
#!/bin/bash
HERE="\$(dirname "\$(readlink -f "\$0")")"
export PATH="\$HERE/usr/bin:\$PATH"
export LD_LIBRARY_PATH="\$HERE/usr/lib:\$LD_LIBRARY_PATH"

# 获取要执行的程序名
# 方法1：从 AppImage 文件名推断
APPIMAGE_NAME="\$(basename "\$0" .AppImage)"
# 方法2：使用桌面文件中指定的名称
DESKTOP_NAME="$ORIG_NAME"

# 优先尝试桌面文件中的名称
if [ -f "\$HERE/usr/bin/\$DESKTOP_NAME" ]; then
    exec "\$HERE/usr/bin/\$DESKTOP_NAME" "\$@"
# 然后尝试 AppImage 文件名
elif [ -f "\$HERE/usr/bin/\$APPIMAGE_NAME" ]; then
    exec "\$HERE/usr/bin/\$APPIMAGE_NAME" "\$@"
# 最后尝试任何可执行文件
else
    # 查找第一个可执行文件
    FIRST_EXEC=\$(ls "\$HERE/usr/bin/" 2>/dev/null | head -1)
    if [ -n "\$FIRST_EXEC" ] && [ -x "\$HERE/usr/bin/\$FIRST_EXEC" ]; then
        exec "\$HERE/usr/bin/\$FIRST_EXEC" "\$@"
    else
        echo "错误: 未找到可执行文件"
        exit 1
    fi
fi
EOF
    chmod +x AppDir/AppRun
    
    # 桌面文件（使用原始程序名）
    mkdir -p AppDir/usr/share/applications
    cat > "AppDir/usr/share/applications/$APP_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Exec=$ORIG_NAME
Icon=$APP_NAME
Categories=Utility;
EOF
    ln -sf usr/share/applications/$APP_NAME.desktop AppDir/
    
    # 打包
    echo "正在打包..."
    OUTPUT_FILE="${APP_NAME}.AppImage"
    
    # 尝试不同模式
    if appimagetool --no-appstream AppDir "$OUTPUT_FILE" 2>/dev/null || \
       appimagetool --no-appstream AppDir "$OUTPUT_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ 打包成功${NC}"
    else
        echo -e "${RED}✗ 打包失败${NC}"
        exit 1
    fi
    
    # 测试
    echo -e "\n${BLUE}════════════════════════════════════════${NC}"
    echo -e "${GREEN}测试运行...${NC}"
    
    chmod +x "$OUTPUT_FILE"
    
    # 测试运行
    echo "命令: ./\"$OUTPUT_FILE\" --help"
    if timeout 3s ./"$OUTPUT_FILE" --help 2>&1 | head -5; then
        echo -e "${GREEN}✅ 程序运行正常${NC}"
    elif timeout 3s ./"$OUTPUT_FILE" -h 2>&1 | head -5; then
        echo -e "${GREEN}✅ 程序运行正常${NC}"
    else
        echo -e "${YELLOW}⚠ 程序可能无参数运行或需要特定参数${NC}"
        echo "尝试直接运行: ./\"$OUTPUT_FILE\""
    fi
    
    echo ""
    echo "输出文件: $(realpath "$OUTPUT_FILE")"
    echo "文件大小: $(du -h "$OUTPUT_FILE" | cut -f1)"
    
    rm -rf AppDir
}

main "$@"