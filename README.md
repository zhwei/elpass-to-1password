# elpass-to-1password

把 Elpass 导出的 JSON 转成 1Password 的 `.1pux` 文件。

只用 Python 标准库，没有第三方依赖。

## 用法

```sh
uv run elpass_to_1password.py input.json -o export.1pux
# 或者
python3 elpass_to_1password.py input.json -o export.1pux
```

然后在 1Password 桌面端「文件 → 导入」里选 1Password，把生成的 `.1pux` 喂进去。

输入可以是一个 JSON 数组，也可以是 `{"items": [...]}` 这种把数组包一层的对象。

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-o, --output` | 输出路径，默认跟输入同名换成 `.1pux` |
| `--vault-name` | 保险库名字，默认 `Elpass` |
| `--account-name` | 账号名字，默认 `Elpass Import` |
| `--email` | 账号邮箱，可以留空 |
| `--unmapped {auto,all,none}` | 没法映射的属性怎么办，见下文，默认 `auto` |
| `--skip-archived` | 不导出 `archived: true` 的条目（默认是导出成回收站条目） |
| `--dump-json` | 额外把 `export.data` 写一份出来，方便肉眼核对 |
| `--show-mapping` | 打印字段映射表后退出 |

## `.1pux` 是什么

就是个 zip 包：

```
export.attributes   导出元信息（version 3）
export.data         accounts → vaults → items 的全部数据
files/              附件，本脚本不产生
```

## 支持的条目类型

Elpass 的 `_type` 对应 1Password 的分类（`categoryUuid`）：

| Elpass `_type` | 1Password 分类 |
| --- | --- |
| `login` | 登录项 `001` |
| `password` | 密码 `005` |
| `securenote` / `note` | 安全备注 `003` |
| `bankcard` / `card` | 银行卡 `002` |
| `identity` | 身份 `004` |

另外还预置了服务器、数据库、护照、会员卡等一堆映射，见代码里的 `TYPE_TO_CATEGORY`。碰到不认识的 `_type` 会兜底成登录项或安全备注，并在 stderr 提示。

## 字段映射

| Elpass | 1Password |
| --- | --- |
| `uuid` | `item.uuid`（哈希成 26 位大写字母数字，1Password 的 ID 形态） |
| `title` | `overview.title` |
| `username` / `password` | `details.loginFields`（密码分类走 `details.password`，其它分类落到区块字段） |
| `notes` | `details.notesPlain` |
| `domains` | `overview.url` + `overview.urls[]`，没写协议的自动补 `https://` |
| `otpURL` | 区块字段 `value.totp`，1Password 会真的算验证码 |
| `tags` | `overview.tags` |
| `customFields[]` | 区块字段，`sensitive: true` → `value.concealed`，否则 `value.string` |
| `favIdx` | `item.favIndex` |
| `archived` | `item.trashed`（Elpass 的归档就是 1Password 的回收站） |
| `passwordHistories[]` | `details.passwordHistory[]`，`voidDateTimestamp` → `time` |
| `createdAt` / `updatedAt` | `item.createdAt` / `item.updatedAt` |

银行卡（`bankcard`）的预置字段，字段 `id` 用的是 1Password 认得的固定名字：

| Elpass | 1Password 字段 |
| --- | --- |
| `cardHolder`（没有就用 `username`） | `cardholder` |
| `cardBrand` | `type`，`value.creditCardType`（`MasterCard` → `mc`，另有 visa / amex / unionpay 等对照表） |
| `cardNumber` | `ccnum`，`value.creditCardNumber` |
| `cardVerificationCode` | `cvv`，`value.concealed` |
| `cardExpiryDateYear` + `cardExpiryDateMonth` | `expiry`，`value.monthYear`（整数 `YYYYMM`） |

### 字段顺序

1Password 按数组顺序渲染字段，脚本保持输入里的原顺序，并把 `indexAtSource` 设成一致的下标。渲染顺序是：

1. 用户名 / 密码（预置字段，永远最前）
2. 无标题区块：一次性密码 → 然后 `customFields` 按原顺序
3. 「Elpass」区块

## 没法映射的属性

1Password 里没有对应位置的属性，默认原样写进一个叫 **Elpass** 的区块，不静默丢弃：

`securityLevel`、`noAutoFill`、`noAutoSubmit`、`noAutoFillOTP`、`cardType`（信用卡/借记卡）、`importSourceUUID`、`passkeyBackupEligible`、`passkeyBackedUp`、`passkeySignatureCounter`、`passkeyAlgorithm`

`--unmapped` 控制这块的行为：

- `auto`（默认）只保留非默认值，避免每条都挂一堆没意义的 `false` / `0`
- `all` 全部保留
- `none` 全部丢弃

脚本不认识的新属性也会自动进这个区块，并在 stderr 列出来提醒你。

### passkey

Elpass 那几个 `passkey*` 属性只是 WebAuthn 凭据的元数据，没有 credential ID、rpId、userHandle 和私钥，光靠它们重建不出 passkey，而 `.1pux` 也没有 passkey 的表示形式。所以这部分只能当元数据保留，导入后不会变成能用的 passkey。

### 创建 / 修改时间

`.1pux` 格式本身有 `item.createdAt` / `item.updatedAt`，脚本原样写进去了。但 1Password 的导入实现有没有沿用这两个值，我没法保证 —— 有可能被重置成导入时刻。

所以脚本**同时**在「Elpass」区块里存一份可读的原始时间（带时区偏移，比如 `2017-02-13 18:08:22 +0800`），即使被重置，信息也还在。

建议先拿两三条试导一次，在 1Password 里确认效果再全量跑。

## 注意

Elpass 导出的 JSON 和生成的 `.1pux` 里都是**明文密码**，用完记得删掉，别提交到仓库里（`.gitignore` 已经挡了 `*.json` 和 `*.1pux`）。
