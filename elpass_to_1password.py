#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""把 Elpass 导出的 JSON 转成 1Password 的 .1pux 文件。

用法：
    uv run elpass2onepassword.py input.json -o export.1pux
    python3 elpass2onepassword.py input.json -o export.1pux

只用标准库，没有第三方依赖。

.1pux 就是一个 zip 包，里面有：
    export.attributes   导出元信息
    export.data         全部账号 / 保险库 / 条目
    files/              附件（本脚本不产生附件）

字段映射见 README 里的表格，或者 python3 elpass2onepassword.py --show-mapping。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 1Password 分类 UUID
# ---------------------------------------------------------------------------

CATEGORY_LOGIN = "001"
CATEGORY_CREDIT_CARD = "002"
CATEGORY_SECURE_NOTE = "003"
CATEGORY_IDENTITY = "004"
CATEGORY_PASSWORD = "005"
CATEGORY_DOCUMENT = "006"
CATEGORY_SOFTWARE_LICENSE = "100"
CATEGORY_BANK_ACCOUNT = "101"
CATEGORY_DATABASE = "102"
CATEGORY_DRIVER_LICENSE = "103"
CATEGORY_OUTDOOR_LICENSE = "104"
CATEGORY_MEMBERSHIP = "105"
CATEGORY_PASSPORT = "106"
CATEGORY_REWARD_PROGRAM = "107"
CATEGORY_SSN = "108"
CATEGORY_WIRELESS_ROUTER = "109"
CATEGORY_SERVER = "110"
CATEGORY_EMAIL_ACCOUNT = "111"
CATEGORY_API_CREDENTIAL = "112"
CATEGORY_MEDICAL_RECORD = "113"
CATEGORY_SSH_KEY = "114"

# Elpass 的 _type -> 1Password categoryUuid
TYPE_TO_CATEGORY = {
    "login": CATEGORY_LOGIN,
    "password": CATEGORY_PASSWORD,
    "note": CATEGORY_SECURE_NOTE,
    "secure_note": CATEGORY_SECURE_NOTE,
    "securenote": CATEGORY_SECURE_NOTE,
    "card": CATEGORY_CREDIT_CARD,
    "bankcard": CATEGORY_CREDIT_CARD,
    "creditcard": CATEGORY_CREDIT_CARD,
    "credit_card": CATEGORY_CREDIT_CARD,
    "bank_card": CATEGORY_CREDIT_CARD,
    "identity": CATEGORY_IDENTITY,
    "bank_account": CATEGORY_BANK_ACCOUNT,
    "email": CATEGORY_EMAIL_ACCOUNT,
    "email_account": CATEGORY_EMAIL_ACCOUNT,
    "server": CATEGORY_SERVER,
    "database": CATEGORY_DATABASE,
    "api_credential": CATEGORY_API_CREDENTIAL,
    "membership": CATEGORY_MEMBERSHIP,
    "passport": CATEGORY_PASSPORT,
    "driver_license": CATEGORY_DRIVER_LICENSE,
    "outdoor_license": CATEGORY_OUTDOOR_LICENSE,
    "social_security_number": CATEGORY_SSN,
    "reward_program": CATEGORY_REWARD_PROGRAM,
    "software_license": CATEGORY_SOFTWARE_LICENSE,
    "wireless_router": CATEGORY_WIRELESS_ROUTER,
    "document": CATEGORY_DOCUMENT,
    "medical_record": CATEGORY_MEDICAL_RECORD,
    "ssh_key": CATEGORY_SSH_KEY,
}

# 已知能处理的 Elpass 顶层属性，其余的会进「Elpass」区块并给出提示
KNOWN_KEYS = {
    "uuid",
    "_type",
    "title",
    "username",
    "password",
    "notes",
    "domains",
    "otpURL",
    "tags",
    "customFields",
    "favIdx",
    "createdAt",
    "updatedAt",
    "archived",
    "securityLevel",
    "noAutoFill",
    "noAutoSubmit",
    "noAutoFillOTP",
    "passkeyBackupEligible",
    "passkeyBackedUp",
    "passkeySignatureCounter",
    "passkeyAlgorithm",
    "importSourceUUID",
    "passwordHistories",
    # bankcard 分类
    "cardNumber",
    "cardBrand",
    "cardType",
    "cardExpiryDateMonth",
    "cardExpiryDateYear",
    "cardVerificationCode",
    "cardHolder",
    "cardholderName",
}

# Elpass 的 cardBrand -> 1Password 银行卡类型菜单的取值
CARD_BRAND_TO_1PASSWORD = {
    "visa": "visa",
    "mastercard": "mc",
    "master card": "mc",
    "mc": "mc",
    "americanexpress": "amex",
    "american express": "amex",
    "amex": "amex",
    "discover": "discover",
    "jcb": "jcb",
    "diners": "diners",
    "diners club": "diners",
    "dinersclub": "diners",
    "unionpay": "unionpay",
    "union pay": "unionpay",
    "银联": "unionpay",
    "maestro": "maestro",
    "carteblanche": "carteblanche",
    "carte blanche": "carteblanche",
    "laser": "laser",
    "elo": "elo",
    "hipercard": "hipercard",
    "visaelectron": "visaelectron",
    "visa electron": "visaelectron",
}

# 这些属性 1Password 没有对应位置，只能原样保留到「Elpass」区块
UNMAPPED_KEYS = [
    ("cardType", None),  # 信用卡 / 借记卡，1Password 的银行卡分类没有这个字段
    ("importSourceUUID", None),
    ("securityLevel", 0),
    ("noAutoFill", False),
    ("noAutoSubmit", False),
    ("noAutoFillOTP", False),
    ("passkeyBackupEligible", False),
    ("passkeyBackedUp", False),
    ("passkeySignatureCounter", 0),
    ("passkeyAlgorithm", 0),
]

MAPPING_DOC = """\
Elpass 属性                  1Password (.1pux) 位置
--------------------------- ------------------------------------------------
uuid                        item.uuid（转成 26 位大写字母数字，1Password 的 ID 格式）
_type                       item.categoryUuid（login -> 001，见 TYPE_TO_CATEGORY）
title                       item.overview.title
username                    details.loginFields[designation=username]（非登录类进区块字段）
password                    details.loginFields[designation=password]（密码类进 details.password）
notes                       details.notesPlain
domains                     overview.url（第一个）+ overview.urls[]，缺协议时补 https://
otpURL                      区块字段 value.totp（标题 one-time password）
tags                        overview.tags
customFields[].title        区块字段 title
customFields[].value        区块字段 value.concealed / value.string
customFields[].sensitive    决定用 concealed 还是 string
favIdx                      item.favIndex
createdAt                   item.createdAt（秒），同时以可读文本存进「Elpass」区块
updatedAt                   item.updatedAt（秒），同时以可读文本存进「Elpass」区块
archived                    item.trashed（Elpass 的归档就是 1Password 的回收站）
passwordHistories[]         details.passwordHistory[]（value + voidDateTimestamp -> time）
--------------------------- ------------------------------------------------
bankcard 分类（categoryUuid 002）的预置字段：
cardHolder / username       区块字段 id=cardholder（持卡人）
cardBrand                   区块字段 id=type，value.creditCardType（visa / mc / amex ...）
cardNumber                  区块字段 id=ccnum，value.creditCardNumber
cardVerificationCode        区块字段 id=cvv，value.concealed
cardExpiryDateYear + Month  区块字段 id=expiry，value.monthYear（整数 YYYYMM）
--------------------------- ------------------------------------------------
以下 1Password 没有对应字段，默认原样写入名为「Elpass」的区块（--unmapped 控制）：
cardType（信用卡/借记卡）, importSourceUUID,
securityLevel, noAutoFill, noAutoSubmit, noAutoFillOTP,
passkeyBackupEligible, passkeyBackedUp, passkeySignatureCounter, passkeyAlgorithm
"""


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def one_password_id(seed: str) -> str:
    """把任意字符串映射成 26 位大写字母数字，贴近 1Password 自己的 ID 形态。"""
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return encoded[:26]


def hex_id(seed: str) -> str:
    """区块字段用的 32 位大写十六进制 ID。"""
    return hashlib.md5(seed.encode("utf-8")).hexdigest().upper()


def normalize_timestamp(value: Any) -> int | None:
    """Elpass 用秒；顺手兼容毫秒。"""
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number > 100_000_000_000:  # 毫秒
        number //= 1000
    return number


def format_timestamp(timestamp: int) -> str:
    """按本机时区格式化成可读时间，带时区偏移，避免歧义。"""
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S %z")
    )


def to_url(domain: str) -> str:
    domain = str(domain).strip()
    if not domain:
        return ""
    if "://" in domain:
        return domain
    return "https://" + domain.lstrip("/")


def scalar_to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float, str)):
        return str(value)
    return json.dumps(value, ensure_ascii=False)


def make_field(title: str, value: dict, field_id: str, index: int) -> dict:
    raw = next(iter(value.values()), "")
    return {
        "title": title,
        "id": field_id,
        "value": value,
        "indexAtSource": index,
        "guarded": False,
        "multiline": isinstance(raw, str) and "\n" in raw,
        "dontGenerate": False,
        "inputTraits": {
            "keyboard": "default",
            "correction": "default",
            "capitalization": "default",
        },
    }


# ---------------------------------------------------------------------------
# 转换
# ---------------------------------------------------------------------------


class Converter:
    def __init__(self, unmapped: str = "auto", skip_archived: bool = False) -> None:
        self.unmapped = unmapped  # auto / all / none
        self.skip_archived = skip_archived
        self.warnings: list[str] = []
        self.unknown_keys: dict[str, int] = {}
        self.skipped = 0

    # -- 区块 ---------------------------------------------------------------

    def _build_main_section(self, entry: dict, uuid: str) -> dict | None:
        """otpURL + customFields 放在一个无标题区块里。"""
        fields: list[dict] = []
        index = 0

        otp_url = entry.get("otpURL")
        if otp_url:
            fields.append(
                make_field(
                    "one-time password",
                    {"totp": str(otp_url)},
                    hex_id(f"{uuid}:otp"),
                    index,
                )
            )
            index += 1

        custom_fields = entry.get("customFields") or []
        if not isinstance(custom_fields, list):
            self.warnings.append(f"{uuid}: customFields 不是数组，已跳过")
            custom_fields = []

        for position, custom in enumerate(custom_fields):
            if not isinstance(custom, dict):
                self.warnings.append(f"{uuid}: customFields[{position}] 不是对象，已跳过")
                continue
            unknown = set(custom) - {"title", "value", "sensitive"}
            for key in unknown:
                self._note_unknown(f"customFields[].{key}")
            title = custom.get("title") or ""
            raw_value = custom.get("value")
            text = scalar_to_text(raw_value)
            value = {"concealed": text} if custom.get("sensitive") else {"string": text}
            fields.append(
                make_field(title, value, hex_id(f"{uuid}:custom:{position}"), index)
            )
            index += 1

        if not fields:
            return None
        return {
            "title": "",
            "name": "Section_" + hex_id(f"{uuid}:main"),
            "fields": fields,
        }

    def _build_password_history(self, entry: dict) -> list[dict]:
        """Elpass 的 passwordHistories -> 1Password 的 details.passwordHistory。

        Elpass 的 voidDateTimestamp 是「这个密码作废的时间」，
        1Password 的 time 语义一致，直接对应。
        """
        histories = entry.get("passwordHistories") or []
        if not isinstance(histories, list):
            self.warnings.append(f"{entry.get('uuid')}: passwordHistories 不是数组，已跳过")
            return []

        result = []
        for position, history in enumerate(histories):
            if not isinstance(history, dict):
                self.warnings.append(
                    f"{entry.get('uuid')}: passwordHistories[{position}] 不是对象，已跳过"
                )
                continue
            for key in set(history) - {"value", "voidDateTimestamp"}:
                self._note_unknown(f"passwordHistories[].{key}")
            value = history.get("value")
            if value is None:
                continue
            result.append(
                {
                    "value": str(value),
                    "time": normalize_timestamp(history.get("voidDateTimestamp")) or 0,
                }
            )
        result.sort(key=lambda item: item["time"])
        return result

    def _build_card_section(self, entry: dict, uuid: str) -> dict | None:
        """银行卡分类的预置字段，字段 id 必须用 1Password 的固定名字才会被认出来。"""
        fields: list[dict] = []

        def add(title: str, field_id: str, value: dict) -> None:
            fields.append(make_field(title, value, field_id, len(fields)))

        holder = (
            entry.get("cardHolder")
            or entry.get("cardholderName")
            or entry.get("username")
        )
        if holder:
            add("cardholder name", "cardholder", {"string": str(holder)})

        brand = entry.get("cardBrand")
        if brand:
            key = str(brand).strip().lower()
            mapped = CARD_BRAND_TO_1PASSWORD.get(key)
            if mapped is None:
                mapped = key.replace(" ", "")
                self.warnings.append(
                    f"{entry.get('uuid')}: 不认识的 cardBrand={brand!r}，"
                    f"原样写成 {mapped!r}，1Password 里可能显示为空"
                )
            add("type", "type", {"creditCardType": mapped})

        number = entry.get("cardNumber")
        if number:
            add("number", "ccnum", {"creditCardNumber": str(number)})

        cvv = entry.get("cardVerificationCode")
        if cvv:
            add("verification number", "cvv", {"concealed": str(cvv)})

        year = entry.get("cardExpiryDateYear")
        month = entry.get("cardExpiryDateMonth")
        if year and month:
            try:
                add("expiry date", "expiry", {"monthYear": int(year) * 100 + int(month)})
            except (TypeError, ValueError):
                self.warnings.append(
                    f"{entry.get('uuid')}: 有效期解析失败（{year!r}/{month!r}），已跳过"
                )
        elif year or month:
            self.warnings.append(
                f"{entry.get('uuid')}: 有效期只有年或只有月，1Password 需要两者，已跳过"
            )

        if not fields:
            return None
        return {
            "title": "",
            "name": "Section_" + hex_id(f"{uuid}:card"),
            "fields": fields,
        }

    def _build_elpass_section(self, entry: dict, uuid: str) -> dict | None:
        """1Password 没有对应位置的属性，原样保留。"""
        if self.unmapped == "none":
            return None

        fields: list[dict] = []
        index = 0

        def add(title: str, raw: Any) -> None:
            nonlocal index
            fields.append(
                make_field(
                    title,
                    {"string": scalar_to_text(raw)},
                    hex_id(f"{uuid}:elpass:{title}"),
                    index,
                )
            )
            index += 1

        # 1Password 导入时有可能把创建/修改时间重置成导入时刻，
        # 所以这里再存一份可读的原始时间，信息不至于丢掉。
        for key in ("createdAt", "updatedAt"):
            timestamp = normalize_timestamp(entry.get(key))
            if timestamp is not None:
                add(key, format_timestamp(timestamp))

        for key, default in UNMAPPED_KEYS:
            if key not in entry:
                continue
            value = entry[key]
            if self.unmapped == "auto" and value == default:
                continue  # 默认值没有保留价值
            add(key, value)

        # 脚本没见过的属性一律保留，避免丢数据
        for key in sorted(set(entry) - KNOWN_KEYS):
            self._note_unknown(key)
            add(key, entry[key])

        if not fields:
            return None
        return {
            "title": "Elpass",
            "name": "Section_" + hex_id(f"{uuid}:elpass"),
            "fields": fields,
        }

    def _note_unknown(self, key: str) -> None:
        self.unknown_keys[key] = self.unknown_keys.get(key, 0) + 1

    # -- 条目 ---------------------------------------------------------------

    def convert_item(self, entry: dict, position: int) -> dict | None:
        if not isinstance(entry, dict):
            self.warnings.append(f"第 {position} 条不是对象，已跳过")
            return None

        if self.skip_archived and entry.get("archived"):
            self.skipped += 1
            return None

        source_uuid = str(entry.get("uuid") or f"elpass-item-{position}")
        uuid = one_password_id(source_uuid)

        raw_type = str(entry.get("_type") or "login").lower()
        category = TYPE_TO_CATEGORY.get(raw_type)
        if category is None:
            category = CATEGORY_LOGIN if entry.get("password") else CATEGORY_SECURE_NOTE
            self.warnings.append(
                f"{source_uuid}: 未知的 _type={entry.get('_type')!r}，按 {category} 处理"
            )

        username = entry.get("username")
        password = entry.get("password")

        details: dict[str, Any] = {
            "loginFields": [],
            "notesPlain": entry.get("notes") or "",
            "sections": [],
            "passwordHistory": self._build_password_history(entry),
        }

        if category == CATEGORY_LOGIN:
            if username:
                details["loginFields"].append(
                    {
                        "value": str(username),
                        "id": "username",
                        "name": "username",
                        "fieldType": "T",
                        "designation": "username",
                    }
                )
            if password:
                details["loginFields"].append(
                    {
                        "value": str(password),
                        "id": "password",
                        "name": "password",
                        "fieldType": "P",
                        "designation": "password",
                    }
                )
        elif category == CATEGORY_PASSWORD:
            if password:
                details["password"] = str(password)
            if username:
                details["sections"].append(
                    {
                        "title": "",
                        "name": "Section_" + hex_id(f"{uuid}:credential"),
                        "fields": [
                            make_field(
                                "username",
                                {"string": str(username)},
                                hex_id(f"{uuid}:username"),
                                0,
                            )
                        ],
                    }
                )
        else:
            if category == CATEGORY_CREDIT_CARD:
                card_section = self._build_card_section(entry, uuid)
                if card_section:
                    details["sections"].append(card_section)
                if username and not (
                    entry.get("cardHolder") or entry.get("cardholderName")
                ):
                    username = None  # 已经当持卡人写进去了，别再重复一遍

            # 其它分类没有 loginFields，用户名密码落到区块字段
            credential_fields = []
            if username:
                credential_fields.append(
                    make_field(
                        "username",
                        {"string": str(username)},
                        hex_id(f"{uuid}:username"),
                        len(credential_fields),
                    )
                )
            if password:
                credential_fields.append(
                    make_field(
                        "password",
                        {"concealed": str(password)},
                        hex_id(f"{uuid}:password"),
                        len(credential_fields),
                    )
                )
            if credential_fields:
                details["sections"].append(
                    {
                        "title": "",
                        "name": "Section_" + hex_id(f"{uuid}:credential"),
                        "fields": credential_fields,
                    }
                )

        main_section = self._build_main_section(entry, uuid)
        if main_section:
            details["sections"].append(main_section)

        elpass_section = self._build_elpass_section(entry, uuid)
        if elpass_section:
            details["sections"].append(elpass_section)

        domains = entry.get("domains") or []
        if isinstance(domains, str):
            domains = [domains]
        urls = [to_url(domain) for domain in domains if str(domain).strip()]

        overview: dict[str, Any] = {
            "title": entry.get("title") or "",
            "subtitle": "",
            "url": urls[0] if urls else "",
            "urls": [{"label": "website", "url": url} for url in urls],
            "tags": [str(tag) for tag in (entry.get("tags") or [])],
            "ainfo": str(username) if username else "",
            "ps": 0,
            "pbe": 0,
            "pgrng": False,
        }

        item: dict[str, Any] = {
            "uuid": uuid,
            "favIndex": int(entry.get("favIdx") or 0),
            "createdAt": normalize_timestamp(entry.get("createdAt")) or 0,
            "updatedAt": normalize_timestamp(entry.get("updatedAt"))
            or normalize_timestamp(entry.get("createdAt"))
            or 0,
            "trashed": bool(entry.get("archived")),
            "categoryUuid": category,
            "details": details,
            "overview": overview,
        }
        return item

    # -- 顶层 ---------------------------------------------------------------

    def convert(
        self,
        entries: list,
        account_name: str,
        email: str,
        vault_name: str,
    ) -> dict:
        items = []
        for position, entry in enumerate(entries):
            item = self.convert_item(entry, position)
            if item is not None:
                items.append(item)

        return {
            "accounts": [
                {
                    "attrs": {
                        "accountName": account_name,
                        "name": account_name,
                        "avatar": "",
                        "email": email,
                        "uuid": one_password_id("elpass-account"),
                        "domain": "https://my.1password.com/",
                    },
                    "vaults": [
                        {
                            "attrs": {
                                "uuid": one_password_id("elpass-vault"),
                                "desc": "Imported from Elpass",
                                "avatar": "",
                                "name": vault_name,
                                "type": "P",
                            },
                            "items": items,
                        }
                    ],
                }
            ]
        }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def load_entries(path: Path) -> list:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "records", "entries"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    raise SystemExit(f"无法识别的输入格式：{type(data).__name__}")


def write_1pux(export_data: dict, output: Path) -> None:
    attributes = {
        "version": 3,
        "description": "1Password Unencrypted Export",
        "createdAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("export.attributes", json.dumps(attributes, ensure_ascii=False))
        archive.writestr(
            "export.data", json.dumps(export_data, ensure_ascii=False, indent=2)
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="把 Elpass 导出的 JSON 转成 1Password 的 .1pux 文件",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", nargs="?", type=Path, help="Elpass 导出的 JSON 文件")
    parser.add_argument(
        "-o", "--output", type=Path, help="输出的 .1pux 路径，默认与输入同名"
    )
    parser.add_argument("--vault-name", default="Elpass", help="保险库名字，默认 Elpass")
    parser.add_argument(
        "--account-name", default="Elpass Import", help="账号名字，默认 Elpass Import"
    )
    parser.add_argument("--email", default="", help="账号邮箱，可留空")
    parser.add_argument(
        "--unmapped",
        choices=("auto", "all", "none"),
        default="auto",
        help="1Password 没有对应字段的属性怎么处理："
        "auto 只保留非默认值（默认），all 全部保留，none 丢弃",
    )
    parser.add_argument(
        "--skip-archived",
        action="store_true",
        help="不导出 archived=true 的条目（默认是导出成 trashed=true，进 1Password 回收站）",
    )
    parser.add_argument(
        "--dump-json", type=Path, help="额外把 export.data 写一份到这个路径，方便检查"
    )
    parser.add_argument(
        "--show-mapping", action="store_true", help="打印字段映射表后退出"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.show_mapping:
        print(MAPPING_DOC)
        return 0

    if args.input is None:
        parser.error("需要指定输入文件（或用 --show-mapping 查看映射表）")

    entries = load_entries(args.input)
    converter = Converter(unmapped=args.unmapped, skip_archived=args.skip_archived)
    export_data = converter.convert(
        entries,
        account_name=args.account_name,
        email=args.email,
        vault_name=args.vault_name,
    )

    output = args.output or args.input.with_suffix(".1pux")
    write_1pux(export_data, output)

    if args.dump_json:
        args.dump_json.parent.mkdir(parents=True, exist_ok=True)
        args.dump_json.write_text(
            json.dumps(export_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    item_count = len(export_data["accounts"][0]["vaults"][0]["items"])
    print(f"读取 {len(entries)} 条，写出 {item_count} 条 -> {output}")
    if converter.skipped:
        print(f"跳过 archived 条目 {converter.skipped} 条")
    for warning in converter.warnings:
        print(f"警告：{warning}", file=sys.stderr)
    if converter.unknown_keys:
        print("下面这些属性脚本没有专门处理，已原样放进「Elpass」区块：", file=sys.stderr)
        for key, count in sorted(converter.unknown_keys.items()):
            print(f"  {key}（{count} 次）", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
