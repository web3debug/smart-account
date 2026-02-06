#!/bin/bash

# 一键部署脚本 - 部署 NonceTracker 和 SmartAccount 合约
# 使用方法: ./deploy.sh [network]
# 示例: ./deploy.sh mainnet
# 示例: ./deploy.sh local (使用本地 anvil 节点)

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查必要的工具
check_requirements() {
    if ! command -v forge &> /dev/null; then
        print_error "forge 未安装，请先安装 Foundry"
        exit 1
    fi
}

# 加载环境变量
load_env() {
    if [ -f .env ]; then
        print_info "加载 .env 文件"
        export $(cat .env | grep -v '^#' | xargs)
    fi
}

# 获取网络配置
get_network_config() {
    local network=$1
    
    case $network in
        local)
            RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
            PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
            print_info "使用本地网络: $RPC_URL"
            ;;
        mainnet)
            RPC_URL="${RPC_URL:-https://rpc.consciousnesschain.com}"
            print_warn "使用主网，请确认私钥和配置"
            ;;
        *)
            print_error "未知网络: $network"
            print_info "支持的网络: local, mainnet"
            exit 1
            ;;
    esac
}

# 验证配置
validate_config() {
    if [ -z "$PRIVATE_KEY" ]; then
        print_error "未设置 PRIVATE_KEY 环境变量"
        print_info "请设置 PRIVATE_KEY 或在 .env 文件中配置"
        exit 1
    fi
    
    if [ -z "$RPC_URL" ]; then
        print_error "未设置 RPC_URL 环境变量"
        print_info "请设置 RPC_URL 或在 .env 文件中配置"
        exit 1
    fi
}

# 编译合约
build_contracts() {
    print_info "编译合约..."
    cd "$(dirname "$0")"
    forge build
    if [ $? -ne 0 ]; then
        print_error "编译失败"
        exit 1
    fi
    print_info "编译成功"
}

# 部署合约
deploy_contracts() {
    local network=$1
    print_info "开始部署合约到 $network..."
    
    cd "$(dirname "$0")"
    
    # 构建基础命令
    local cmd="forge script script/Deploy.sol:DeployScript \
        --rpc-url \"$RPC_URL\" \
        --private-key \"$PRIVATE_KEY\" \
        --broadcast \
        -vvvv"
    
    # 执行部署脚本并捕获输出
    local output_file=$(mktemp)
    if ! eval $cmd 2>&1 | tee "$output_file"; then
        print_error "部署失败"
        rm -f "$output_file"
        exit 1
    fi
    
    # 尝试从输出中提取合约地址
    print_info "=== 部署的合约地址 ==="
    if grep -q "NonceTracker deployed at:" "$output_file"; then
        local nonce_tracker_addr=$(grep "NonceTracker deployed at:" "$output_file" | sed 's/.*NonceTracker deployed at: //' | head -1)
        print_info "NonceTracker: $nonce_tracker_addr"
    fi
    if grep -q "SmartAccount deployed at:" "$output_file"; then
        local smart_account_addr=$(grep "SmartAccount deployed at:" "$output_file" | sed 's/.*SmartAccount deployed at: //' | head -1)
        print_info "SmartAccount: $smart_account_addr"
    fi
    
    rm -f "$output_file"
    print_info "部署成功！"
}

# 主函数
main() {
    local network=${1:-local}
    
    print_info "=== 合约部署脚本 ==="
    print_info "网络: $network"
    
    check_requirements
    load_env
    get_network_config "$network"
    validate_config
    build_contracts
    deploy_contracts "$network"
    
    print_info "=== 部署完成 ==="
}

# 运行主函数
main "$@"
