import abc
import asyncio
import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import time
from typing import Any, Optional
import urllib.parse as urlparse

import aiohttp

import aiohttp.http_parser
import aiohttp.typedefs
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtendedKeyUsageOID

from logger import logger
import scheduler
import units


@dataclass
class ACMEAction:
    newNonce: str
    newOrder: str
    newAccount: str
    revokeCert: str
    keyChange: str

@dataclass
class ACMEOrderAuthorization:
    type: str
    value: str
    authorization: str

@dataclass
class ACMEOrder:
    identifiers: list[ACMEOrderAuthorization]
    finalize: str

@dataclass
class ACMEChallenge:
    authorization: str
    chall: str
    txt_value: str

@dataclass
class CertificateInfo:
    create_at: float

@dataclass
class ACMEResponse:
    headers: aiohttp.typedefs._CIMultiDictProxy
    data: Any

@dataclass
class CertificatePath:
    ca: Path
    key: Path

    @property
    def valid(self):
        return self.ca and self.key and self.ca.exists() and self.key.exists() and self.ca.stat().st_size > 0 and self.key.stat().st_size > 0

ACTION = ACMEAction(
    newNonce='https://acme.zerossl.com/v2/DV90/newNonce',
    newAccount='https://acme.zerossl.com/v2/DV90/newAccount',
    newOrder='https://acme.zerossl.com/v2/DV90/newOrder',
    revokeCert='https://acme.zerossl.com/v2/DV90/revokeCert',
    keyChange='https://acme.zerossl.com/v2/DV90/keyChange'
)
CA_ZEROSSL = "https://acme.zerossl.com/v2/DV90"
USER_AGENT = "acme.sh/3.0.8 (https://github.com/acmesh-official/acme.sh)"
PROJECT_ROOT = Path(__file__).parent.parent
SSL = PROJECT_ROOT / ".ssl"
ECC_KEY_LEN = 256
ZEROSSL_INSTANCES: dict[str, 'ZerosslInstance'] = {}
CHECK_INTERVAL = 60 * 60 * 8
DNS_CHECK_FIRST = 30
DNS_CHECK_INTERVAL = 10
BEFORE_VALIDATE = 60 * 60 * 24 * 7

class DNSRecord(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def add(self, root_domain: str, name: str, value: str):
        raise NotImplementedError
    @abc.abstractmethod
    async def remove(self, root_domain: str, name: str, value: str):
        raise NotImplementedError

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
class TencentDNSPODRecord:
    RecordId: int
    Name: str
    Type: str
    Value: str

class TencentDNSRecord(DNSRecord):
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.__TENCENT_HEADERS = ("x-tc-action", "content-type", "host")
        self.__DNSPOD = "2021-03-23"
        self.__USERAGENT = USER_AGENT

    async def add(self, root_domain: str, name: str, value: str):
        try:
            await self._add_record(root_domain, name, "TXT", value)
        except:
            record_id = await self._get_record_id_by_name(root_domain, name, value, "TXT")
            if record_id is None:
                raise
            await self._modify_record(root_domain, name, record_id, "TXT", value)
    
    async def remove(self, root_domain: str, name: str, value: str):
        record_id = await self._get_record_id_by_name(root_domain, name, value, "TXT")
        if record_id is None:
            return
        await self._delete_record(root_domain, record_id)

    async def _describe_record_list(self, domain: str):
        resp = await self._request(
            "DescribeRecordList",
            {
                "Domain": domain
            }
        )
        results: list[TencentDNSPODRecord] = []
        for record in resp.Response["RecordList"]:
            results.append(
                TencentDNSPODRecord(
                    record["RecordId"],
                    record["Name"],
                    record["Type"],
                    record["Value"]
                )
            )
        return results
    async def _add_record(self, domain: str, sub_domain: str, type: str, value: str) -> int:
        resp = await self._request(
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
    async def _modify_record(self, domain: str, sub_domain: str, record_id: int, type: str, value: str):
        resp = await self._request(
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
    async def _delete_record(self, domain: str, record_id: int):
        resp = await self._request(
            "DeleteRecord",
            {
                "Domain": domain,
                "RecordId": record_id,
            }
        )
        return
    async def _get_record_id_by_name(self, domain: str, name: str, value: str, type: str):
        records = await self._describe_record_list(domain)
        for record in records:
            if record.Name == name and record.Type == type and record.Value == value:
                return record.RecordId
        return None
    async def _request(self, action: str, data: Any = {}, query_params: dict = {}):
        url: str = "/"
        method: str = "POST"
        content_type: str = "application/json"
        timestamp = int(time.time())
        content = self._json_dumps(data or {})
        params_str = urlparse.urlencode(query_params)
        content_type_str = content_type
        raw_headers = {
            "Content-Type": content_type_str,
            "Host": f"dnspod.tencentcloudapi.com",
            "User-Agent": self.__USERAGENT,
            "X-TC-Action": action,
            "X-TC-Client": self.__USERAGENT,
            "X-TC-Timestamp": str(timestamp),
            "X-TC-Version": self.__DNSPOD
        }
        headers: dict[str, str] = dict(sorted(
            raw_headers.items(),
            key=lambda x: x[0]   
        ))
        headers_str = '\n'.join((f"{k}:{v}".lower() for k, v in headers.items() if k.lower() in self.__TENCENT_HEADERS))
        headers_keys = ';'.join((k.lower() for k in headers.keys() if k.lower() in self.__TENCENT_HEADERS))
        canonicalRequest = f"{method}\n{url}\n{params_str}\n{headers_str}\n\n{headers_keys}\n{self._hash_content(content)}"
        date_utc = time.gmtime(timestamp)
        date = f"{date_utc.tm_year:04d}-{date_utc.tm_mon:02d}-{date_utc.tm_mday:02d}"
        sign = f"TC3-HMAC-SHA256\n{timestamp}\n{date}/dnspod/tc3_request\n{self._hash_content(canonicalRequest)}"
        sign = hmac.new(self._signature(f"TC3{self.secret_key}", date, "dnspod", "tc3_request"), sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = f"TC3-HMAC-SHA256 Credential={self.secret_id}/{date}/dnspod/tc3_request, SignedHeaders={headers_keys}, Signature={sign}"
        async with aiohttp.ClientSession(
            base_url=f"https://dnspod.tencentcloudapi.com",
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
    def _hash_content(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest().lower()
    def _signature(self, *args: str):
        key = args[0].encode("utf-8")
        for arg in args[1:]:
            key = hmac.new(key, arg.encode("utf-8"), hashlib.sha256).digest()
        return key          
    def _json_dumps(self, data):
        return json.dumps(data, separators=(",", ":"))

class ZerosslInstance:
    def __init__(self, email: str, root_domain: str, dns_record: DNSRecord):
        self.email = email
        self.root_domain = root_domain
        self.dns_record = dns_record
        self._path = SSL / root_domain
        self._path.mkdir(parents=True, exist_ok=True)
        self._jwt = ""
        self._eab_hmac_key = ""
        self._eab_key_id = ""
        self._share_nonce = ""
        self._ca_data = self.read_ca_json()
        self._domain_data = self.read_domain_json()
        scheduler.run_repeat_later(self.check_certificate, 1, CHECK_INTERVAL)

    async def init(self):
        self.create_account_key()
        await self.get_eab_kid()
        await self.reg_account()

    async def check_certificate(self):
        for subdomains in self._domain_data.values():
            expires = self.get_certificate_expires(subdomains) - BEFORE_VALIDATE - time.time()
            if expires < 0:
                logger.twarning("service.acme_zerossl_v2.warning.certificate_will_validate", subdomains=', '.join(subdomains), expires=units.format_count_datetime(expires + BEFORE_VALIDATE))
                await self.get_certificate(subdomains)
                continue
            logger.tinfo("service.acme_zerossl_v2.info.certificate_expires", subdomains=', '.join(subdomains), expires=units.format_count_datetime(expires + BEFORE_VALIDATE))
                
    async def get_eab_kid(self):
        path = self._path / "ca.json"
        if path.exists() and path.stat().st_size > 0:
            data = json.loads(path.read_text())
            self._eab_key_id = data.get("eab_kid")
            self._eab_hmac_key = data.get("eab_hmac_key")
            return self._eab_key_id
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.zerossl.com/acme/eab-credentials-email",
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": 'application/x-www-form-urlencoded',
                },
                data=f"email={self.email}"
            ) as resp:
                data = await resp.json()
                self._eab_key_id = data.get("eab_kid")
                self._eab_hmac_key = data.get("eab_hmac_key")
                path.write_text(json.dumps({
                    "eab_kid": self._eab_key_id,
                    "eab_hmac_key": self._eab_hmac_key
                }))
                return self._eab_key_id

    async def reg_account(self):
        path = self._path / "account.json"
        if path.exists() and path.stat().st_size > 0:
            return
        eab_protected = self.base64_url_replace(json.dumps({"alg": "HS256","kid": self._eab_key_id, "url": ACTION.newAccount}))
        eab_payload = self.base64_url_replace(self.jwt)
        eab_sign_t = f'{eab_protected}.{eab_payload}'
        keyhex = base64.urlsafe_b64decode(self._eab_hmac_key + "==")
        eab_signature = base64.urlsafe_b64encode(
            hmac.new(keyhex, eab_sign_t.encode('utf-8'), hashlib.sha256).digest()
        ).decode('utf-8').replace('=', '')
        regjson = self.base64_url_replace(json.dumps({
            "contact": [f"mailto:{self.email}"],
            "termsOfServiceAgreed": True,
            "externalAccountBinding": {
                "protected": eab_protected,
                "payload": eab_payload,
                "signature": eab_signature
            }
        }))
        protected = await self.signature_data_body(ACTION.newAccount, {
            "jwk": self.jwt
        }, regjson)
        resp = await self.request(
            ACTION.newAccount,
            regjson,
            {
                "jwk": self.jwt
            }
        )
        headers = resp.headers
        data = resp.data
        path.write_text(json.dumps(data))
        self._ca_data['account_url'] = headers.get("Location")
        self._ca_data["ca_key_hash"] = self.calc_account_key_hash()
        self.save_ca_json()

    async def new_nonce(self):
        if self._share_nonce:
            return self._share_nonce
        async with aiohttp.ClientSession() as session:
            async with session.head(
                ACTION.newNonce,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/jose+json"
                }
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
        return self._share_nonce

    async def request(self, url: str, data: Any, protect: dict[str, Any] = {}) -> ACMEResponse:
        if isinstance(data, (dict, list, tuple)):
            raw_data = json.dumps(data)
        else:
            raw_data = data
        data_body = await self.signature_data_body(url, protect, self.base64_url_replace(raw_data))
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/jose+json"
                }, data=data_body
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
                data = await resp.json()
                if resp.status // 1 == 4:
                    logger.error(f"ACME Error: {data['type']} {data['status']}, detail: {data['detail']}, request data: {raw_data}")
                return ACMEResponse(
                    resp.headers,
                    data
                )

    async def send_order(self, domains: list[str]):
        data = (await self.request(
            ACTION.newOrder,
            {
                "identifiers": [{"type": "dns", "value": domain} for domain in domains]
            },
            {
                "kid": self._ca_data['account_url'],
            }
        )).data
        orders: list[ACMEOrderAuthorization] = []
        for i, value in enumerate(data['authorizations']):
            orders.append(ACMEOrderAuthorization(
                data['identifiers'][i]['type'],
                data['identifiers'][i]['value'],
                value
            ))
        return ACMEOrder(
            orders,
            data['finalize'],
        )

    async def finalize_order(self, subdomains: list[str], order: ACMEOrder):
        path = self._path / f"domain_{self.get_subdomains_hash(subdomains)}.csr"
        csr = path.read_text().replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").replace("\r", "").replace("\n", "").replace(" ", "")
        der = base64.urlsafe_b64encode(base64.b64decode(csr)).decode().rstrip('=')
        resp = await self.request(
            order.finalize,
            {
                "csr": der
            },
            {
                "kid": self._ca_data['account_url'],
            }
        )
        data = resp.data
        status = data['status']
        if status == "valid":
            return data['certificate']
        elif status == "processing":
            while not status == "valid":
                await asyncio.sleep(5)
                link_order_url: str = resp.headers.get("Location") # type: ignore
                data = (await self.request(
                    link_order_url,
                    "",
                    {
                        "kid": self._ca_data['account_url'],
                    }
                )).data
                status = data['status']
                if status == "valid":
                    return data['certificate']
                elif status == "invalid":
                    logger.error(f"finalize failed, data: {data}")
                    return None
        else:
            logger.warning(f"unknown status: {status}, data: {data}")

    async def signature_data_body(self, url: str, protect: dict[str, Any], payload: str):
        protected = self.base64_url_replace(json.dumps({
            "nonce": await self.new_nonce(),
            "url": url,
            "alg": f"ES{ECC_KEY_LEN}",
            **protect
        }))
        return json.dumps({
            "protected": protected,
            "payload": payload,
            "signature": self.sign(f'{protected}.{payload}')
        })

    async def get_certificate(self, subdomains: list[str], force: bool = False) -> Optional[CertificatePath]:

        if not force and self.get_subdomains_hash(subdomains) in self._domain_data and self.get_certificate_expires(subdomains) - BEFORE_VALIDATE - time.time() > 0:
            return CertificatePath(
            self._path / f"fullchain_{self.get_subdomains_hash(subdomains)}.cer", 
            self._path / f"domain_{self.get_subdomains_hash(subdomains)}.key"
        )

        self.create_subdomains_key(subdomains)
        order = await self.send_order(subdomains)
        txt_values: dict[str, ACMEChallenge] = {
            i.value: await self.get_challenge(i) for i in order.identifiers
        }
        # call dns record
        await self.add_record(txt_values)
        
        logger.tinfo("service.acme_zerossl.verify_dns", time=DNS_CHECK_FIRST)       
        await asyncio.sleep(DNS_CHECK_FIRST)
        logger.tinfo("service.acme_zerossl.start_verify")

        status = await self.start_verify(txt_values)
        if not all(status.values()):
            # print failed
            for name, value in status.items():
                if not value:
                    logger.error(f"verify failed, domain: {name}")
            await self.remove_record(txt_values)
            return None
        logger.tinfo("service.acme_zerossl.verify_success")
        # remove dns record
        await self.remove_record(txt_values)

        self.create_subdomains_csr(subdomains)

        link = await self.finalize_order(subdomains, order)
        if not link:
            logger.error("finalize failed")
            return None
        logger.tinfo("service.acme_zerossl.finalize_success")
        await self.download_cert(subdomains, link)
        self._domain_data[self.get_subdomains_hash(subdomains)] = subdomains
        return CertificatePath(
            self._path / f"fullchain_{self.get_subdomains_hash(subdomains)}.cer", 
            self._path / f"domain_{self.get_subdomains_hash(subdomains)}.key"
        )
    
    async def download_cert(self, subdomains: list[str], link: str):
        path = self._path / f"fullchain_{self.get_subdomains_hash(subdomains)}.cer"
        data_body = await self.signature_data_body(link, {
            "kid": self._ca_data['account_url'],
        }, "")
        async with aiohttp.ClientSession() as session:
            async with session.post(
                link,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/jose+json"
                },
                data=data_body
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
                content = await resp.read()
                path.write_bytes(content)
                if not content:
                    logger.error(f"download cert failed, path: {path}")
                    return

    async def remove_record(self, txt_values: dict[str, ACMEChallenge]):
        for name, challenge in txt_values.items():
            name = self.get_domain_name(name)
            logger.debug(f"remove record, name: {name}.{self.root_domain}, value: {challenge.txt_value}")
            await self.dns_record.remove(self.root_domain, name, challenge.txt_value)

    async def add_record(self, txt_values: dict[str, ACMEChallenge]):
        for name, challenge in txt_values.items():
            name = self.get_domain_name(name)
            logger.debug(f"add record, name: {name}.{self.root_domain}, value: {challenge.txt_value}")
            await self.dns_record.add(self.root_domain, name, challenge.txt_value)
        
    async def start_verify(self, domains: dict[str, ACMEChallenge]):
        status: dict[str, bool] = {}
        for domain, challenge in domains.items():
            status[domain] = await self.verify(domain, challenge)
        return status

    async def verify(self, domain: str, challenge: ACMEChallenge):
        data_body = await self.signature_data_body(challenge.chall, {
            "kid": self._ca_data['account_url'],
        }, self.base64_url_replace(json.dumps({})))
        async with aiohttp.ClientSession() as session:
            async with session.post(
                challenge.chall,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/jose+json"
                }, data=data_body
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
                data = await resp.json()
                status = data['status']
                if status == 'valid':
                    return True
                elif status == 'invalid':
                    return False
                elif status == "processing":
                    while not status == "valid":
                        logger.debug(f"verify processing, domain: {domain}")
                        await asyncio.sleep(DNS_CHECK_INTERVAL)
                        auth_url = challenge.authorization
                        data_body = await self.signature_data_body(auth_url, {
                            "kid": self._ca_data['account_url'],
                        }, "")
                        async with session.post(
                            auth_url,
                            headers={
                                "User-Agent": USER_AGENT,
                                "Content-Type": "application/jose+json"
                            }, data=data_body
                        ) as resp:
                            self._share_nonce = resp.headers.get("Replay-Nonce")
                            data = await resp.json()
                            status = data.get("status")
                            if status == "valid":
                                logger.success(f"verify success, domain: {domain}")
                                return True
                            elif status == "invalid":
                                logger.error(f"verify failed, domain: {domain}")
                                return False
                    if status == "valid":
                        logger.success(f"verify success, domain: {domain}")
                        return True
                else:
                    logger.warning(f"unknown status: {status}, data: {data}")
                    return False
        return False
    
    async def get_challenge(self, order: ACMEOrderAuthorization):
        domain, authorization = order.value, order.authorization
        data_body = await self.signature_data_body(authorization, {
            "kid": self._ca_data['account_url'],
        }, "")
        async with aiohttp.ClientSession() as session:
            async with session.post(
                authorization,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/jose+json"
                }, data=data_body
            ) as resp:
                self._share_nonce = resp.headers.get("Replay-Nonce")
                data = await resp.json()
                token, chall = '', ''
                for i in (data['challenges']):
                    if i['type'] == 'dns-01':
                        token = i['token']
                        chall = i['url']
                        break
                key_authorization = token + "." + self.sha256_urlb64(self.jwt)
                txt_value = self.sha256_urlb64(key_authorization)
                return ACMEChallenge(
                    authorization,
                    chall, 
                    txt_value
                )
    
    def get_certificate_expires(self, subdomains: list[str]) -> float:
        path = self._path / f"fullchain_{self.get_subdomains_hash(subdomains)}.cer"
        if not path.exists() or path.stat().st_size == 0:
            return 0
        certificate = x509.load_pem_x509_certificate(path.read_bytes(), default_backend())
        return certificate.not_valid_after_utc.timestamp()

    def get_domain_name(self, name: str):
        return ("_acme-challenge." + name.removesuffix(self.root_domain).replace("*.", "")).rstrip(".")

    def sha256_urlb64(self, data: str):
        return base64.urlsafe_b64encode(hashlib.sha256(data.replace(' ', '').encode("utf8")).digest()).decode().replace('=', '')

    def create_subdomains_key(self, subdomains: list[str]):
        path = self._path / f"domain_{self.get_subdomains_hash(subdomains)}.key"
        if path.exists() and path.stat().st_size > 0:
            return

        self.write_random_key(path)

    def create_subdomains_csr(self, subdomains: list[str]):
        path = self._path / f"domain_{self.get_subdomains_hash(subdomains)}.csr"
        if path.exists() and path.stat().st_size > 0:
            return
        path.write_bytes(b'')
        private_key = serialization.load_pem_private_key(
            (self._path / f"domain_{self.get_subdomains_hash(subdomains)}.key").read_bytes(),
            password=None,
            backend=default_backend()
        )
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subdomains[0]),
        ])
        alt_names = [x509.DNSName(d) for d in subdomains]
        san = x509.SubjectAlternativeName(alt_names)

        eku_extension = x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,  # TLS Web Server Authentication
            ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS Web Client Authentication
        ])
        csr = (
            x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .add_extension(eku_extension, critical=False)
                .add_extension(san, critical=False)
                .sign(private_key, hashes.SHA256(), default_backend()) # type: ignore
        )
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        path.write_bytes(pem.encode())
        logger.debug(f"create_domain_csr {subdomains} success")
        logger.debug("\n" + pem)

    def create_account_key(self):
        path = self._path / "account.key"
        if path.exists() and path.stat().st_size > 0:
            return
        self.write_random_key(path)

    def write_random_key(self, path: Path):
        path.write_bytes(
            ec.generate_private_key(
                ec.SECP256R1(), 
                default_backend()
            ).private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    @property
    def jwt(self):
        if self._jwt:
            return self._jwt
        path = self._path / "account.key"
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None, backend=default_backend())
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        x, y = public_numbers.x, public_numbers.y
        x_bytes, y_bytes = x.to_bytes(32, 'big'), y.to_bytes(32, 'big')
        x64, y64 = base64.urlsafe_b64encode(x_bytes).decode('utf-8').rstrip('='), base64.urlsafe_b64encode(y_bytes).decode('utf-8').rstrip('=')
        self._jwt = json.dumps({
            "crv": "P-256",
            "kty": "EC",
            "x": x64,
            "y": y64
        })
        return self._jwt
    
    def read_ca_json(self):
        path = self._path / "ca.json"
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text())
        return {}
    
    def save_ca_json(self):
        path = self._path / "ca.json"
        path.write_text(json.dumps(self._ca_data))

    def read_domain_json(self):
        path = self._path / "domain.json"
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text())
        return {}

    def save_domain_json(self):
        path = self._path / "domain.json"
        path.write_text(json.dumps(self._domain_data))


    def base64_url_replace(self, data: str):
        return base64.urlsafe_b64encode(data.encode("utf-8")).decode().replace('=', '')

    def sign(self, data: str):
        path = self._path / "account.key"
        private_key = serialization.load_pem_private_key(
            path.read_bytes(),
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign( # type: ignore
            data.encode(),
            ec.ECDSA(hashes.SHA256()) # type: ignore
        )
        der_signature_r, der_signature_s = utils.decode_dss_signature(signature)
        der_signature_hex = binascii.hexlify(
            der_signature_r.to_bytes(32, byteorder='big') + der_signature_s.to_bytes(32, byteorder='big'))
        return base64.urlsafe_b64encode(bytes.fromhex(der_signature_hex.decode('ascii'))).decode('ascii').replace('=', '')
    
    def calc_account_key_hash(self):
        path = self._path / "account.key"
        hash_object = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_object.update(chunk)
        return base64.b64encode(hash_object.digest()).decode()
    
    async def __aenter__(self):
        await self.init()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.save_ca_json()
        self.save_domain_json()

    def get_subdomains_hash(self, subdomains: list[str]):
        return get_subdomains_hash(subdomains)

def get_zerossl_instance(email: str, domain: str, dns: DNSRecord):
    instance = None
    key = hashlib.sha256(email.encode() + domain.encode()).hexdigest()
    if key in ZEROSSL_INSTANCES:
        instance = ZEROSSL_INSTANCES[key]
    else:
        instance = ZerosslInstance(email, domain, dns)
        ZEROSSL_INSTANCES[key] = instance
    instance.dns_record = dns
    return instance

def get_subdomains_hash(subdomains: list[str]):
    return hashlib.sha256(''.join((hashlib.sha256(subdomain.encode()).hexdigest() for subdomain in subdomains)).encode()).hexdigest()
        