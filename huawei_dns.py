# Mail: tongdongdong@outlook.com
import sys
import random
import time
import json
import requests
import os
import traceback
import logging
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

class HuaWeiApi():
    def __init__(self, ACCESSID, SECRETKEY, REGION = 'cn-east-3'):
        self.AK = ACCESSID
        self.SK = SECRETKEY
        self.region = REGION
        self.client = DnsClient.new_builder().with_credentials(BasicCredentials(self.AK, self.SK)).with_region(DnsRegion.value_of(self.region)).build()
        self.zone_id = self.get_zones()

    def del_record(self, domain, record):
        request = DeleteRecordSetsRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record
        response = self.client.delete_record_sets(request)
        result = json.loads(str(response))
        return result

    def get_record(self, domain, length, sub_domain, record_type):
        request = ListRecordSetsWithLineRequest()
        request.limit = length
        request.type = record_type
        if sub_domain == '@':
            request.name = domain + "."
        else:
            request.name = sub_domain + '.' + domain + "."
        response = self.client.list_record_sets_with_line(request)
        data = json.loads(str(response))
        result = {}
        records_temp = []
        for record in data['recordsets']:
            if (sub_domain == '@' and domain + "." == record['name']) or (sub_domain + '.' + domain + "." == record['name']):
                record['line'] = self.line_format(record['line'])
                record['value'] = '1.1.1.1'
                records_temp.append(record)
        result['data'] = {'records': records_temp}
        return result

    def create_record(self, domain, sub_domain, value, record_type, line, ttl):
        request = CreateRecordSetWithLineRequest()
        request.zone_id = self.zone_id[domain + '.']
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        request.body = CreateRecordSetWithLineReq(
            type = record_type,
            name = name,
            ttl = ttl,
            weight = 1,
            records = value if isinstance(value, list) else [value],
            line = self.line_format(line)
        )
        response = self.client.create_record_set_with_line(request)
        result = json.loads(str(response))
        return result

    def change_record(self, domain, record_id, sub_domain, value, record_type, line, ttl):
        request = UpdateRecordSetRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record_id
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        request.body = UpdateRecordSetReq(
            name = name,
            type = record_type,
            ttl = ttl,
            records = value if isinstance(value, list) else [value]
        )
        response = self.client.update_record_set(request)
        result = json.loads(str(response))
        return result

    def get_zones(self):
        request = ListPublicZonesRequest()
        response = self.client.list_public_zones(request)
        result = json.loads(str(response))
        zone_id = {}
        for zone in result['zones']:
            zone_id[zone['name']] = zone['id'] 
        return zone_id

    def line_format(self, line):
        lines = {
            '默认' : 'default_view',
            '电信' : 'Dianxin',
            '联通' : 'Liantong',
            '移动' : 'Yidong',
            '境外' : 'Abroad',
            'default_view' : '默认',
            'Dianxin' : '电信',
            'Liantong' : '联通',
            'Yidong' : '移动',
            'Abroad' : '境外',
        }
        return lines.get(line, None)

# 环境变量配置
def get_env_or_raise(key):
    value = os.getenv(key)
    if not value:
        raise ValueError(f"环境变量 {key} 未设置")
    return value

try:
    DOMAINS_JSON = get_env_or_raise("DOMAINS")
    SECRETID = get_env_or_raise("SECRETID")
    SECRETKEY = get_env_or_raise("SECRETKEY")
except ValueError as e:
    logging.error(str(e))
    sys.exit(1)

try:
    DOMAINS = json.loads(DOMAINS_JSON)
except json.JSONDecodeError as e:
    logging.error(f"DOMAINS JSON 解析错误: {e}")
    sys.exit(1)

# 其他配置
AFFECT_NUM = 3  # 默认影响记录数
DNS_SERVER = os.getenv("DNS_SERVER", "3.1")  # 使用华为云DNS，支持 3 和 3.1 两种模式
TTL = int(os.getenv("TTL", 300))  # 默认 TTL 300 秒
RECORD_TYPE = sys.argv[1] if len(sys.argv) >= 2 else "A"  # 记录类型 A/AAAA
REGION_HW = os.getenv("REGION_HW", "cn-east-3")

# API 配置
API_1 = 'https://api.hostmonit.com/get_optimization_ip'
API_2 = 'https://ip.164746.xyz/'
API_3 = 'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip'
API_4 = 'https://api.vvhan.com/tool/cf_ip'

# 根据记录类型选择 API
API = API_4 # 默认使用 vvhan API

# 添加全局缓存变量
_cached_ip_data = {
    "ipv4": None,
    "ipv6": None
}

def parse_custom_ips(ip_str):
    return [{"ip": ip.strip()} for ip in ip_str.split(',') if ip.strip()]

# 自定义 IP 配置
self_cm_cfips = ""
self_cu_cfips = ""
self_ct_cfips = ""
self_def_cfips = ""

self_cm_cfips_list = parse_custom_ips(self_cm_cfips)
self_cu_cfips_list = parse_custom_ips(self_cu_cfips)
self_ct_cfips_list = parse_custom_ips(self_ct_cfips)
self_def_cfips_list = parse_custom_ips(self_def_cfips)

def mask_domain(domain):
    """隐藏域名信息，只显示首尾字符"""
    if not domain:
        return "***"
    if len(domain) <= 2:
        return "*" * len(domain)
    return f"{domain[0]}***{domain[-1]}"

def get_optimization_ip():
    """获取优化后的 IP 地址，支持缓存"""
    global _cached_ip_data
    record_type = RECORD_TYPE  # 当前请求的记录类型
    
    # 如果已有对应类型的缓存数据，直接返回
    if record_type == "A" and _cached_ip_data["ipv4"]:
        return _cached_ip_data["ipv4"]
    elif record_type == "AAAA" and _cached_ip_data["ipv6"]:
        return _cached_ip_data["ipv6"]
        
    try:
        if API == API_4:  # vvhan API
            response = requests.get(API, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if not result.get("success") or "data" not in result:
                logging.error(f"API 返回异常数据: {json.dumps(result)}")
                return None
            
            # 处理 IPv4 数据
            ipv4_data = result["data"].get("v4", {})
            ipv4_result = {
                "code": 200,
                "info": {}
            }
            
            # 处理 IPv6 数据
            ipv6_data = result["data"].get("v6", {})
            ipv6_result = {
                "code": 200,
                "info": {"DEF": []}
            }
            
            # 处理 IPv4 数据
            for line_code in ["CM", "CU", "CT"]:
                if line_code in ipv4_data:
                    ips = sorted(ipv4_data[line_code], key=lambda x: x.get("latency", float('inf')))
                    ipv4_result["info"][line_code] = [{"ip": ip["ip"]} for ip in ips[:AFFECT_NUM]]
            
            # 处理 IPv6 数据
            if ipv6_data:
                all_v6_ips = []
                seen_ips = set()
                for isp_ips in ipv6_data.values():
                    for ip in isp_ips:
                        if ip["ip"] not in seen_ips:
                            seen_ips.add(ip["ip"])
                            all_v6_ips.append(ip)
                
                sorted_v6_ips = sorted(all_v6_ips, key=lambda x: x.get("latency", float('inf')))
                ipv6_result["info"]["DEF"] = [{"ip": ip["ip"]} for ip in sorted_v6_ips[:AFFECT_NUM]]
            
            # 缓存结果
            _cached_ip_data["ipv4"] = ipv4_result
            _cached_ip_data["ipv6"] = ipv6_result
            
            # 根据请求类型返回对应结果
            return _cached_ip_data["ipv6"] if record_type == "AAAA" else _cached_ip_data["ipv4"]
            
    except requests.exceptions.RequestException as e:
        logging.error(f"请求优化 IP API 失败: {str(e)}")
    except Exception as e:
        logging.error(f"获取优化 IP 异常: {str(e)}")
        logging.debug(traceback.format_exc())
    return None

def validate_ips(ips):
    """验证并去重 IP 列表"""
    if not ips:
        return []
    
    seen_ips = set()
    valid_ips = []
    
    for ip_info in ips:
        ip = ip_info.get("ip")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            valid_ips.append(ip_info)
    
    return valid_ips[:AFFECT_NUM]

def handle_dns_records(cloud, domain, sub_domain, line_config):
    """处理 DNS 记录的核心逻辑"""
    masked_domain = mask_domain(domain)
    masked_subdomain = mask_domain(sub_domain)
    
    # 如果是 IPv6，只处理默认线路
    if RECORD_TYPE == "AAAA":
        line_config = ["DEF"]
        logging.info("IPv6 模式：仅更新默认线路")
    
    line_map = {
        "CM": ("移动", self_cm_cfips_list),
        "CU": ("联通", self_cu_cfips_list),
        "CT": ("电信", self_ct_cfips_list),
        "DEF": ("默认", self_def_cfips_list)
    }

    for line_code in line_config:
        line_name, custom_ips = line_map.get(line_code, (None, None))
        if not line_name:
            logging.warning(f"跳过无效线路配置: {line_code}")
            continue

        # 获取现有记录
        try:
            records = cloud.get_record(domain, 100, sub_domain, RECORD_TYPE)
        except Exception as e:
            logging.error(f"获取记录失败: {str(e)}")
            continue

        # 过滤当前线路记录
        current_records = [
            {"recordId": r["id"], "value": r["value"]}
            for r in records.get("data", {}).get("records", [])
            if r.get("line") == line_name
        ]

        # 获取可用 IP
        api_result = get_optimization_ip()
        if not api_result:
            logging.error("无法获取优化 IP，使用自定义 IP")
            optimized_ips = custom_ips
        else:
            optimized_ips = api_result["info"].get(line_code, [])[:3] + custom_ips

        valid_ips = validate_ips(optimized_ips)
        if not valid_ips:
            logging.error(f"{line_code} 线路无有效 IP")
            continue

        # 提取所有有效IP地址
        new_ips = [ip["ip"] for ip in valid_ips]
        
        try:
            if current_records:
                # 更新现有记录，使用IP列表
                record_id = current_records[0]["recordId"]
                cloud.change_record(domain, record_id, sub_domain, new_ips, RECORD_TYPE, line_name, TTL)
                logging.info(f"更新记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")
            else:
                # 创建新记录，使用IP列表
                cloud.create_record(domain, sub_domain, new_ips, RECORD_TYPE, line_name, TTL)
                logging.info(f"创建记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")
            
            # 删除多余的记录（如果存在）
            for record in current_records[1:]:
                cloud.del_record(domain, record["recordId"])
                logging.info(f"删除多余记录 {masked_subdomain}.{masked_domain} {line_name}")

        except Exception as e:
            logging.error(f"记录操作失败: {str(e)}")
            logging.debug(traceback.format_exc())

class Config:
    """配置管理类"""
    # API 配置
    API_ENDPOINTS = {
        'hostmonit': 'https://api.hostmonit.com/get_optimization_ip',
        '345673': 'https://ip.164746.xyz/',
        'wetest': 'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
        'vvhan': 'https://api.vvhan.com/tool/cf_ip'
    }
    
    # 运营商配置
    ISP_CONFIG = {
        "CM": ("移动", "self_cm_cfips"),
        "CU": ("联通", "self_cu_cfips"),
        "CT": ("电信", "self_ct_cfips"),
        "DEF": ("默认", "self_def_cfips")
    }
    
    def __init__(self):
        # 从环境变量和命令行参数加载配置
        self.AFFECT_NUM = 3
        self.DNS_SERVER = os.getenv("DNS_SERVER", "3.1")
        self.TTL = int(os.getenv("TTL", 300))
        self.RECORD_TYPE = sys.argv[1] if len(sys.argv) >= 2 else "A"
        self.REGION_HW = os.getenv("REGION_HW", "cn-east-3")
        self.API = self.API_ENDPOINTS['vvhan']  # 默认使用 vvhan API
        
        # 加载自定义IP配置
        self.self_cm_cfips = ""
        self.self_cu_cfips = ""
        self.self_ct_cfips = ""
        self.self_def_cfips = ""

class IPManager:
    """IP管理类"""
    def __init__(self, config):
        self.config = config
        self._custom_ips = {}
        self.load_custom_ips()
    
    def load_custom_ips(self):
        """加载自定义IP配置"""
        for isp_code, (_, ip_var) in Config.ISP_CONFIG.items():
            ip_str = getattr(self.config, ip_var, "")
            self._custom_ips[isp_code] = parse_custom_ips(ip_str)
    
    def get_valid_ips(self, isp_code, api_ips=None):
        """获取有效的IP列表"""
        custom_ips = self._custom_ips.get(isp_code, [])
        if api_ips:
            return validate_ips(api_ips[:self.config.AFFECT_NUM] + custom_ips)
        return validate_ips(custom_ips)

class DNSManager:
    """DNS记录管理类"""
    def __init__(self, cloud, config, ip_manager):
        self.cloud = cloud
        self.config = config
        self.ip_manager = ip_manager
    
    def update_records(self, domain, sub_domain, line_config):
        """更新DNS记录"""
        masked_domain = mask_domain(domain)
        masked_subdomain = mask_domain(sub_domain)
        
        # 如果是 IPv6，只处理默认线路
        if self.config.RECORD_TYPE == "AAAA":
            line_config = ["DEF"]
            logging.info(f"{masked_subdomain}.{masked_domain}: IPv6模式，仅更新默认线路")
        
        for line_code in line_config:
            line_name, custom_ips = Config.ISP_CONFIG.get(line_code, (None, None))
            if not line_name:
                logging.warning(f"跳过无效线路配置: {line_code}")
                continue
                
            try:
                self._handle_single_line(domain, sub_domain, line_code, line_name)
            except Exception as e:
                logging.error(f"{masked_subdomain}.{masked_domain} {line_code}: {str(e)}")
    
    def _handle_single_line(self, domain, sub_domain, line_code, line_name):
        """处理单个线路的DNS记录"""
        masked_domain = mask_domain(domain)
        masked_subdomain = mask_domain(sub_domain)
        
        # 获取现有记录
        records = self.cloud.get_record(domain, 100, sub_domain, self.config.RECORD_TYPE)
        current_records = [
            {"recordId": r["id"], "value": r["value"]}
            for r in records.get("data", {}).get("records", [])
            if r.get("line") == line_name
        ]

        # 获取优化IP
        api_result = get_optimization_ip()
        if api_result:
            if self.config.RECORD_TYPE == "AAAA":
                optimized_ips = api_result.get("ipv6_info", {}).get("DEF", [])
            else:
                optimized_ips = api_result.get("info", {}).get(line_code, [])
        else:
            optimized_ips = []

        # 获取有效IP
        valid_ips = self.ip_manager.get_valid_ips(line_code, optimized_ips)
        if not valid_ips:
            raise ValueError(f"{line_code} 线路无有效 IP")

        # 提取IP地址
        new_ips = [ip["ip"] for ip in valid_ips]
        
        try:
            # 更新记录
            if current_records:
                record_id = current_records[0]["recordId"]
                self.cloud.change_record(
                    domain, record_id, sub_domain, new_ips,
                    self.config.RECORD_TYPE, line_name, self.config.TTL
                )
                logging.info(f"更新记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")
            else:
                self.cloud.create_record(
                    domain, sub_domain, new_ips,
                    self.config.RECORD_TYPE, line_name, self.config.TTL
                )
                logging.info(f"创建记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")

            # 删除多余记录
            for record in current_records[1:]:
                self.cloud.del_record(domain, record["recordId"])
                logging.info(f"删除多余记录 {masked_subdomain}.{masked_domain} {line_name}")
            
        except Exception as e:
            logging.error(f"记录操作失败 {masked_subdomain}.{masked_domain} {line_name}: {str(e)}")
            raise

def main():
    """主函数"""
    try:
        # 初始化配置
        config = Config()
        
        # 初始化华为云
        cloud = HuaWeiApi(
            SECRETID, 
            SECRETKEY, 
            config.REGION_HW if config.DNS_SERVER == "3.1" else None
        )
        
        # 初始化管理器
        ip_manager = IPManager(config)
        dns_manager = DNSManager(cloud, config, ip_manager)
        
        # 处理域名
        for domain, sub_domains in DOMAINS.items():
            if not isinstance(sub_domains, dict):
                logging.error(f"域名 {mask_domain(domain)} 配置格式错误")
                continue
                
            for sub_domain, lines in sub_domains.items():
                if not isinstance(lines, list):
                    logging.error(f"子域名 {mask_domain(sub_domain)} 配置格式错误")
                    continue
                    
                dns_manager.update_records(domain, sub_domain, lines)
                
    except Exception as e:
        logging.error(f"程序执行失败: {str(e)}")
        logging.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("用户中断执行")
    except Exception as e:
        logging.error(f"程序异常: {str(e)}")
        logging.debug(traceback.format_exc())
