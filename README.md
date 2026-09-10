# elpass-to-1password

把 Elpass 导出的 JSON 转成 1Password 的 `.1pux` 文件。

只用 Python 标准库，没有第三方依赖。

## 用法

```sh
uv run elpass_to_1password.py Elpass.elpassexport -o export.1pux
# 或者
python3 elpass_to_1password.py Elpass.elpassexport -o export.1pux
```

然后在 1Password 桌面端「文件 → 导入」里选 1Password，把生成的 `.1pux` 喂进去。

输入是 Elpass 导出的 `.elpassexport` 文件，内容是 JSON。可以是一个数组，也可以是 `{"items": [...]}` 这种把数组包一层的对象。不校验后缀，别的后缀照样能跑。

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-o, --output` | 输出路径，默认跟输入同名换成 `.1pux` |
| `--vault-name` | 保险库名字，默认 `Elpass` |
| `--account-name` | 账号名字，默认 `Elpass Import` |
| `--email` | 账号邮箱，可以留空 |
| `--import-tag` | 每个条目加的标签，默认 `elpass`，传空字符串则不加 |
| `--attachments {inline,items,skip}` | 附件怎么导，见下文，默认 `inline` |
| `--attachments-dir` | 附件目录，默认找「输入文件名 + `.attachments`」 |
| `--unmapped {auto,all,none}` | 没法映射的属性怎么办，见下文，默认 `auto` |
| `--skip-archived` | 不导出 `archived: true` 的条目（默认是导出成 1Password 的归档条目） |
| `--dump-json` | 额外把 `export.data` 写一份出来，方便肉眼核对 |
| `--show-mapping` | 打印字段映射表后退出 |

## `.1pux` 是什么

就是个 zip 包：

```
export.attributes   导出元信息（version 3，timestamp 是 Unix 秒）
export.data         accounts → vaults → items 的全部数据
files/              附件本体，文件名是 <documentId>___<原文件名>
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
| `identification` | 按 `identificationType` 挑：护照 `106`、驾照 `103`、社保号 `108`，其余（身份证等）当安全备注 `003` |

另外还预置了服务器、数据库、护照、会员卡等一堆映射，见代码里的 `TYPE_TO_CATEGORY`。碰到不认识的 `_type` 会兜底成登录项或安全备注，并在 stderr 提示。

## 字段映射

| Elpass | 1Password |
| --- | --- |
| `uuid` | `item.uuid`（哈希成 26 位大写字母数字，1Password 的 ID 形态） |
| `title` | `overview.title` |
| `username` / `password` | `details.loginFields`（密码分类走 `details.password`，其它分类落到区块字段） |
| `notes` | `details.notesPlain` |
| `domains` | `overview.url` + `overview.urls[]`，没写协议的自动补 `https://` |
| `otpURL` | 区块字段 `value.totp`，字段 id 带 `TOTP_` 前缀，1Password 会真的算验证码 |
| `tags` | `overview.tags`，另外每条都加一个 `elpass` 标签，导入后好筛 |
| `customFields[]` | 区块字段，`sensitive: true` → `value.concealed`，否则 `value.string`；缺 `value` 当空值 |
| `otherFields` | 数组时同 `customFields`；对象时每个键一个文本字段，`issuingBank` 见下表 |
| `pin` | 区块字段，银行卡用 1Password 的固定 id `pin` |
| `identificationType` / `identificationNumber` | 区块字段 `identification type` / `identification number`（号码按敏感信息存 concealed） |
| `attachments[]` | 区块字段 `value.file` + zip 里的 `files/<documentId>__<原文件名>`，见下文 |
| `favIdx` | `item.favIndex` |
| `archived` | `item.state`（`archived` / `active`，1Password 原生的归档状态） |
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
| `pin` | `pin`，落在「Additional Details」区块 |
| `otherFields.issuingBank` | `bank`（发卡行），落在「Contact Information」区块 |

`otherFields` 里没有专门映射的键，按普通文本字段导入，并在跑完后列出来 —— 看到了告诉我，可以再往模板里加。

### 附件

`.elpassexport` 里只有附件的元信息，本体在**输入文件名后面加 `.attachments`** 的目录里（也认换掉后缀的 `Elpass.attachments`），按附件 uuid 分子目录：

```
Elpass.elpassexport
Elpass.elpassexport.attachments/
  11111111-2222-3333-4444-555555555555/id_ed25519
  66666666-7777-8888-9999-AAAAAAAAAAAA/license.pdf
```

脚本会自动找这个目录（也可以用 `--attachments-dir` 指定），把文件本体打进 `.1pux` 的 `files/<documentId>__<原文件名>`。子目录优先按附件 uuid 找，找不到再按条目 uuid 找；目录里优先取跟 `fileName` 同名的文件，只有一个文件时就取那个。

`--attachments` 决定附件怎么挂：

- `inline`（默认）附件挂在原条目上，是一个 `value.file` 字段。对着 1Password 真实导出验证过，就是这种形态。
- `items` 每个附件单独建一个「文档」条目，用 `details.documentAttributes` 引用。附件跟原条目分家，靠标题、标签和备注里的「来自条目「xxx」」关联。
- `skip` 不打包本体，只把元信息留在「Elpass」区块。

`fileSize` 以磁盘上的实际大小为准，对不上会警告。`fileModificationDate` 1Password 没地方放，写成了 zip 里该文件的修改时间。找不到本体的附件会警告，并把元信息留在「Elpass」区块里，方便你手动补。

### 字段顺序

1Password 按数组顺序渲染字段，脚本保持输入里的原顺序，并把 `indexAtSource` 设成一致的下标。渲染顺序是：

1. 用户名 / 密码（预置字段，永远最前）
2. 无标题区块：一次性密码 → PIN / 证件 → `customFields` → `otherFields` → 附件
3. 银行卡的「Additional Details」区块（PIN / 证件）
4. 「Elpass」区块

## 没法映射的属性

1Password 里没有对应位置的属性，默认原样写进一个叫 **Elpass** 的区块，不静默丢弃：

`securityLevel`、`noAutoFill`、`noAutoSubmit`、`noAutoFillOTP`、`cardType`（信用卡/借记卡）、`importSourceUUID`、`passkeyBackupEligible`、`passkeyBackedUp`、`passkeySignatureCounter`、`passkeyAlgorithm`

`--unmapped` 控制这块的行为：

- `auto`（默认）只保留非默认值，避免每条都挂一堆没意义的 `false` / `0`
- `all` 全部保留
- `none` 全部丢弃

脚本不认识的新属性也会自动进这个区块，并在 stderr 列出来提醒你。`customFields` / `otherFields` 要是形状对不上（不是 `[{title, value, sensitive}]` 那种数组），也会整个原样塞进来，不会硬转。

### passkey

Elpass 那几个 `passkey*` 属性只是 WebAuthn 凭据的元数据，没有 credential ID、rpId、userHandle 和私钥，光靠它们重建不出 passkey，而 `.1pux` 也没有 passkey 的表示形式。所以这部分只能当元数据保留，导入后不会变成能用的 passkey。

### 创建 / 修改时间

`.1pux` 格式本身有 `item.createdAt` / `item.updatedAt`，脚本原样写进去了。但 1Password 的导入实现有没有沿用这两个值，我没法保证 —— 有可能被重置成导入时刻。

所以脚本**同时**在「Elpass」区块里存一份可读的原始时间（带时区偏移，比如 `2017-02-13 18:08:22 +0800`），即使被重置，信息也还在。

建议先拿两三条试导一次，在 1Password 里确认效果再全量跑。

## 跟 1Password 真实导出对齐

字段名和结构不是照着格式说明猜的，是拿一份 1Password 自己导出的 `.1pux` 逐层比对过的 —— 两边在 `export.attributes`、`account.attrs`、`vault.attrs`、item、`overview`、`details`、`sections`、`fields`、`loginFields`、`urls[]` 每一层的键集合都一致。

有两处**格式说明跟真实导出不符，以真实导出为准**：

- `export.attributes` 里的时间戳键叫 `timestamp`，不是说明里写的 `createdAt`。
- `files/` 里文件名的分隔符是**两个**下划线（`<documentId>__<原文件名>`），说明里的例子写成了三个。

另外说明里的字段类型清单没有 `file`，但真实导出里确实有 `value.file` 形态的附件字段。

## 注意

Elpass 导出的 `.elpassexport` 和生成的 `.1pux` 里都是**明文密码**，用完记得删掉，别提交到仓库里（`.gitignore` 已经挡了 `*.elpassexport`、`*.json` 和 `*.1pux`）。
