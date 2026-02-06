# Solidity

**Solidity is a programming language for writing smart contracts.**

## Usage

### Install Dependencies

```shell
forge install
```

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

### Deploy

#### 一键部署脚本

使用 `deploy.sh` 脚本可以一键部署 NonceTracker 和 SmartAccount 合约：

```shell
# 部署到本地网络（需要先启动 anvil）
./deploy.sh local

# 部署到主网
./deploy.sh mainnet
```

**环境变量配置：**

在 `solidity` 目录下创建 `.env` 文件，配置以下变量：

```bash
# 私钥（不要包含 0x 前缀）
PRIVATE_KEY=your_private_key_here

# 自定义 RPC URL（可选）
# RPC_URL=https://your-rpc-url.com
```
