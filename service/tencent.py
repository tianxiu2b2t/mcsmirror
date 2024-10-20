from dataclasses import dataclass, field
import enum
import hashlib
import hmac
import json
import time
from typing import Any, Optional
import urllib.parse as urlparse

import aiohttp

from const import const
import env

@dataclass
class TencentHTTPResponse:
    Response: dict[str, Any]

    @property
    def RequestId(self) -> str:
        return self.Response["RequestId"]
    
    def raise_for_error(self):
        if "Error" in self.Response:
            code = self.Response["Error"]["Code"]
            message = self.Response["Error"]["Message"]
            raise RuntimeError(f"Error {code}: {message}")

@dataclass
class DNSRecord:
    RecordId: int
    Name: str
    Type: str
    Value: str

TENCENT_HEADERS = ("x-tc-action", "content-type", "host")
class Service(enum.Enum):
    SSL = "2019-12-05"
    DNSPOD = "2021-03-23"

async def request(service: Service, action: str, data: Any = {}, query_params: dict = {}):
    url: str = "/"
    method: str = "POST"
    content_type: str = "application/json"
    timestamp = int(time.time())
    content = json_dumps(data or {})
    params_str = urlparse.urlencode(query_params)
    content_type_str = content_type
    client = const.user_agent
    raw_headers = {
        "Content-Type": content_type_str,
        "Host": f"{service.name.lower()}.tencentcloudapi.com",
        "User-Agent": client,
        "X-TC-Action": action,
        "X-TC-Client": client,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": service.value
    }
    headers: dict[str, str] = dict(sorted(
        raw_headers.items(),
        key=lambda x: x[0]   
    ))
    headers_str = '\n'.join((f"{k}:{v}".lower() for k, v in headers.items() if k.lower() in TENCENT_HEADERS))
    headers_keys = ';'.join((k.lower() for k in headers.keys() if k.lower() in TENCENT_HEADERS))
    canonicalRequest = f"{method}\n{url}\n{params_str}\n{headers_str}\n\n{headers_keys}\n{hash_content(content)}"
    date_utc = time.gmtime(timestamp)
    date = f"{date_utc.tm_year:04d}-{date_utc.tm_mon:02d}-{date_utc.tm_mday:02d}"
    sign = f"TC3-HMAC-SHA256\n{timestamp}\n{date}/{service.name.lower()}/tc3_request\n{hash_content(canonicalRequest)}"
    sign = hmac.new(signature(f"TC3{TENCENT_TOKEN}", date, service.name.lower(), "tc3_request"), sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = f"TC3-HMAC-SHA256 Credential={TENCENT_ID}/{date}/{service.name.lower()}/tc3_request, SignedHeaders={headers_keys}, Signature={sign}"
    async with aiohttp.ClientSession(
        base_url=f"https://{service.name.lower()}.tencentcloudapi.com",
        headers={
            "Authorization": authorization,
            **headers
        }
    ) as session:
        async with session.post(
            url,
            params=query_params,
            data=content,
        ) as resp:
            resp.raise_for_status()
            response_data = await resp.json()
            response = TencentHTTPResponse(**response_data)
            return response
def hash_content(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest().lower()

def signature(*args: str):
    key = args[0].encode("utf-8")
    for arg in args[1:]:
        key = hmac.new(key, arg.encode("utf-8"), hashlib.sha256).digest()
    return key          

def json_dumps(data):
    return json.dumps(data, separators=(",", ":"))

TENCENT_ID = env.get_env("TENCENT_KEY")
TENCENT_TOKEN = env.get_env("TENCENT_SECRET")

async def dnspod_describe_record_list(domain: str):
    resp = await request(
        Service.DNSPOD,
        "DescribeRecordList",
        {
            "Domain": domain
        }
    )
    results: list[DNSRecord] = []
    for record in resp.Response["RecordList"]:
        results.append(
            DNSRecord(
                record["RecordId"],
                record["Name"],
                record["Type"],
                record["Value"]
            )
        )
    return results

async def dnspod_add_record(domain: str, sub_domain: str, type: str, value: str) -> int:
    resp = await request(
        Service.DNSPOD,
        "CreateRecord",
        {
            "Domain": domain,
            "SubDomain": sub_domain,
            "RecordType": type,
            "RecordLine": "默认",
            "Value": value,
        }
    )
    resp.raise_for_error()
    return resp.Response["RecordId"]

async def dnspod_modify_record(domain: str, sub_domain: str, record_id: int, type: str, value: str):
    resp = await request(
        Service.DNSPOD,
        "ModifyRecord",
        {
            "Domain": domain,
            "SubDomain": sub_domain,
            "RecordId": record_id,
            "RecordType": type,
            "RecordLine": "默认",
            "Value": value,
        }
    )
    resp.raise_for_error()
    return resp.Response["RecordId"]

async def dnspod_delete_record(domain: str, record_id: int):
    resp = await request(
        Service.DNSPOD,
        "DeleteRecord",
        {
            "Domain": domain,
            "RecordId": record_id,
        }
    )
    return

async def dnspod_get_record_id_by_name(domain: str, name: str, type: str):
    records = await dnspod_describe_record_list(domain)
    for record in records:
        if record.Name == name and record.Type == type:
            return record.RecordId
    return None
async def init():
    ...