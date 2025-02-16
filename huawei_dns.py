# Mail: tongdongdong@outlook.com
import sys
import json
import requests
import os
import traceback
import logging
import time
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
API_LIST = [
    {
        'url': 'https://api.vvhan.com/tool/cf_ip1',
        'name': 'vvhan',
        'id': 1  # API序号
    },
    {
        'url': 'https://api.hostmonit.com/get_optimization_ip',
        'name': 'hostmonit',
        'id': 2
    },
    {
        'url': 'https://ip.164746.xyz/',
        'name': '164746',
        'id': 3
    },
    {
        'url': 'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip',
        'name': 'wetest',
        'id': 4
    }
]

# 添加缓存时间控制
_cached_ip_data = {
    "ipv4": {"data": None, "timestamp": None},
    "ipv6": {"data": None, "timestamp": None}
}
CACHE_EXPIRE_TIME = 300  # 5分钟缓存过期

def get_cached_data(record_type):
    cache = _cached_ip_data["ipv4" if record_type == "A" else "ipv6"]
    if (cache["data"] is None or 
        cache["timestamp"] is None or 
        time.time() - cache["timestamp"] > CACHE_EXPIRE_TIME):
        return None
    return cache["data"]

def set_cached_data(record_type, data):
    cache_key = "ipv4" if record_type == "A" else "ipv6"
    _cached_ip_data[cache_key] = {
        "data": data,
        "timestamp": time.time()
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

def get_api_priority():
    """从环境变量获取API优先级配置"""
    priority_str = os.getenv("API_PRIORITY", "")
    if not priority_str:
        return API_LIST  # 如果没有配置，使用默认优先级
    
    try:
        # 环境变量格式示例: "2,1,4,3" 表示 hostmonit -> vvhan -> wetest -> 164746
        priority_list = [int(x.strip()) for x in priority_str.split(',') if x.strip().isdigit()]
        
        # 创建API ID到API的映射
        api_map = {api['id']: api for api in API_LIST}
        
        # 根据优先级序号重新排序API列表
        sorted_apis = []
        for priority in priority_list:
            if priority in api_map:
                api = api_map[priority].copy()
                api['priority'] = len(sorted_apis) + 1  # 设置新的优先级
                sorted_apis.append(api)
        
        # 添加未在优先级列表中的API
        remaining_apis = [api for api in API_LIST if api['id'] not in priority_list]
        for api in remaining_apis:
            api_copy = api.copy()
            api_copy['priority'] = len(sorted_apis) + 1
            sorted_apis.append(api_copy)
        
        if not sorted_apis:
            logging.warning("无有效的API优先级配置，使用默认顺序")
            return API_LIST
            
        return sorted_apis
        
    except Exception as e:
        logging.warning(f"API优先级配置解析失败: {str(e)}，使用默认顺序")
        return API_LIST

def process_ip_data(data, record_type, api_name):
    """处理IP数据，返回处理后的结果"""
    result = {
        "code": 200,
        "info": {}
    }
    
    if api_name == 'vvhan':
        # vvhan API 格式处理
        ip_data = data.get("v6" if record_type == "AAAA" else "v4", {})
        if not ip_data:
            return None
            
        all_ips = []
        seen_ips = set()
        for isp_ips in ip_data.values():
            for ip in isp_ips:
                if ip["ip"] not in seen_ips:
                    seen_ips.add(ip["ip"])
                    all_ips.append(ip)
        
        sorted_ips = sorted(all_ips, key=lambda x: x.get("latency", float('inf')))
        best_ips = [{"ip": ip["ip"]} for ip in sorted_ips[:AFFECT_NUM]]
        
        for line_code in ["CM", "CU", "CT"]:
            if line_code in ip_data:
                line_ips = sorted(ip_data[line_code], key=lambda x: x.get("latency", float('inf')))
                result["info"][line_code] = [{"ip": ip["ip"]} for ip in line_ips[:AFFECT_NUM]]
        
        result["info"]["DEF"] = best_ips
        
    elif api_name in ['hostmonit', 'wetest']:
        # hostmonit 和 wetest API 格式处理
        if not isinstance(data, list):
            return None
            
        # 按运营商分类IP
        isp_ips = {"CM": [], "CU": [], "CT": [], "DEF": []}
        for ip_info in data:
            ip = ip_info.get("ip")
            isp = ip_info.get("isp", "DEF")
            if ip:
                isp_ips[isp].append({"ip": ip})
        
        # 为每个运营商选择IP
        for isp in isp_ips:
            if isp_ips[isp]:
                result["info"][isp] = isp_ips[isp][:AFFECT_NUM]
        
    elif api_name == 'vps789':
        # vps789 API 格式处理
        if not isinstance(data, dict):
            return None
            
        result["info"] = {
            "CT": [{"ip": ip["ip"]} for ip in data.get("CT", [])[:AFFECT_NUM]],
            "CU": [{"ip": ip["ip"]} for ip in data.get("CU", [])[:AFFECT_NUM]],
            "CM": [{"ip": ip["ip"]} for ip in data.get("CM", [])[:AFFECT_NUM]],
            "DEF": [{"ip": ip["ip"]} for ip in data.get("AllAvg", [])[:AFFECT_NUM]]
        }
    
    return result

def get_optimization_ip(line_config=None):
    """获取优化后的 IP 地址"""
    record_type = RECORD_TYPE
    
    # 检查缓存
    cached_data = get_cached_data(record_type)
    if cached_data:
        return cached_data
    
    sorted_apis = get_api_priority()
    
    for api in sorted_apis:
        try:
            api_id = api['id']
            api_priority = api.get('priority', api_id)
            logging.info(f"尝试从 {api['name']} (ID: {api_id}, 优先级: {api_priority}) 获取IP数据")
            
            response = requests.get(api['url'], timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if api['name'] == 'vvhan':
                if not result.get("success") or "data" not in result:
                    logging.warning(f"{api['name']} API 返回异常数据")
                    continue
                processed_data = process_ip_data(result["data"], record_type, api['name'])
                
            elif api['name'] in ['hostmonit', 'wetest']:
                if not isinstance(result, list):
                    logging.warning(f"{api['name']} API 返回异常数据")
                    continue
                processed_data = process_ip_data(result, record_type, api['name'])
                
            elif api['name'] == 'vps789':
                if result.get("code") != 0 or "data" not in result:
                    logging.warning(f"{api['name']} API 返回异常数据")
                    continue
                processed_data = process_ip_data(result["data"], record_type, api['name'])
            
            if processed_data:
                set_cached_data(record_type, processed_data)
                return processed_data
            
        except Exception as e:
            logging.error(f"{api['name']} API处理异常: {str(e)}")
            continue
    
    error_msg = "所有API都无法获取IP数据"
    logging.error(error_msg)
    raise RuntimeError(error_msg)

def get_line_ips(api_result, line_code, has_default_line):
    """根据线路配置获取对应的IP列表"""
    if has_default_line:
        # 如果配置了默认线路，所有线路都使用默认线路的IP
        return api_result["info"].get("DEF", [])
    else:
        # 否则使用对应线路的IP
        return api_result["info"].get(line_code, [])

def handle_dns_records(cloud, domain, sub_domain, line_config):
    """处理 DNS 记录的核心逻辑"""
    masked_domain = mask_domain(domain)
    masked_subdomain = mask_domain(sub_domain)
    
    # 确保域名格式正确
    domain = domain.rstrip('.')
    if sub_domain == '@':
        full_domain = domain
    else:
        full_domain = f"{sub_domain}.{domain}"
    
    # 判断是否包含默认线路
    has_default_line = "DEF" in line_config
    
    # 获取可用 IP（只请求一次）
    try:
        api_result = get_optimization_ip(line_config)
        if not api_result:
            logging.error("无法获取优化 IP")
            return
    except Exception as e:
        logging.error(f"获取IP数据失败: {str(e)}")
        return

    # 处理每个线路
    for line_code in line_config:
        line_name = {
            "CM": "移动",
            "CU": "联通",
            "CT": "电信",
            "DEF": "默认"
        }.get(line_code)
        
        if not line_name:
            logging.warning(f"跳过无效线路配置: {line_code}")
            continue

        try:
            # 获取现有记录
            records = cloud.get_record(domain, 100, sub_domain, RECORD_TYPE)
            current_records = [
                {"recordId": r["id"], "value": r["value"]}
                for r in records.get("data", {}).get("records", [])
                if r.get("line") == line_name
            ]

            # 获取当前线路的IP
            optimized_ips = get_line_ips(api_result, line_code, has_default_line)
            
            if not optimized_ips:
                logging.error(f"{line_code} 线路无有效 IP")
                continue

            # 提取IP地址
            new_ips = [ip["ip"] for ip in optimized_ips]
            
            try:
                if current_records:
                    # 更新现有记录
                    record_id = current_records[0]["recordId"]
                    cloud.change_record(
                        domain, record_id, sub_domain, new_ips,
                        RECORD_TYPE, line_name, TTL
                    )
                    logging.info(f"更新记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")
                else:
                    # 创建新记录
                    cloud.create_record(
                        domain, sub_domain, new_ips,
                        RECORD_TYPE, line_name, TTL
                    )
                    logging.info(f"创建记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")

                # 删除多余记录
                for record in current_records[1:]:
                    cloud.del_record(domain, record["recordId"])
                    logging.info(f"删除多余记录 {masked_subdomain}.{masked_domain} {line_name}")

            except Exception as e:
                logging.error(f"记录操作失败 {masked_subdomain}.{masked_domain} {line_name}: {str(e)}")
                continue

        except Exception as e:
            logging.error(f"处理记录失败 {masked_subdomain}.{masked_domain} {line_name}: {str(e)}")
            continue

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
        # 修正：添加必要的属性初始化
        self.DOMAINS = DOMAINS
        self.SECRETID = SECRETID
        self.SECRETKEY = SECRETKEY
        self.AFFECT_NUM = 3
        self.DNS_SERVER = os.getenv("DNS_SERVER", "3.1")
        self.TTL = int(os.getenv("TTL", 300))
        self.RECORD_TYPE = sys.argv[1] if len(sys.argv) >= 2 else "A"
        self.REGION_HW = os.getenv("REGION_HW", "cn-east-3")
        
        # 修正：移除未使用的 API 相关配置
        self.API_PRIORITY = os.getenv("API_PRIORITY", "")
        
        # 加载自定义IP配置
        self.self_cm_cfips = ""
        self.self_cu_cfips = ""
        self.self_ct_cfips = ""
        self.self_def_cfips = ""

    def validate(self):
        """验证配置的有效性"""
        if not self.SECRETID or not self.SECRETKEY:
            raise ValueError("缺少华为云认证信息")
        if not self.DOMAINS:
            raise ValueError("未配置域名信息")
        if self.RECORD_TYPE not in ["A", "AAAA"]:
            raise ValueError(f"不支持的记录类型: {self.RECORD_TYPE}")
        if self.TTL < 60:
            raise ValueError("TTL不能小于60秒")
        if not 1 <= self.AFFECT_NUM <= 10:
            raise ValueError("AFFECT_NUM必须在1-10之间")

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
    
    def validate_ips(self, ips):
        """验证IP地址列表的有效性"""
        valid_ips = []
        for ip in ips:
            if isinstance(ip, dict) and "ip" in ip:
                valid_ips.append(ip)
        return valid_ips
    
    def get_valid_ips(self, isp_code, api_ips=None):
        """获取有效的IP列表"""
        custom_ips = self._custom_ips.get(isp_code, [])
        if api_ips:
            return self.validate_ips(api_ips[:self.config.AFFECT_NUM] + custom_ips)
        return self.validate_ips(custom_ips)

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
        
        # 确保域名格式正确
        domain = domain.rstrip('.')  # 移除末尾的点
        if sub_domain == '@':
            full_domain = domain
        else:
            full_domain = f"{sub_domain}.{domain}"
        
        # 获取可用 IP（传入线路配置）
        try:
            api_result = get_optimization_ip(line_config)
            if not api_result:
                logging.error("无法获取优化 IP")
                return
        except Exception as e:
            logging.error(f"获取IP数据失败: {str(e)}")
            return

        # 处理每个线路
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
        
        try:
            # 获取现有记录
            records = self.cloud.get_record(domain, 100, sub_domain, self.config.RECORD_TYPE)
            if not records or "data" not in records:
                raise ValueError("获取记录失败")
                
            current_records = [
                {"recordId": r["id"], "value": r["value"]}
                for r in records.get("data", {}).get("records", [])
                if r.get("line") == line_name
            ]

            # 获取优化IP
            api_result = get_optimization_ip()
            if not api_result or "info" not in api_result:
                raise ValueError("无法获取优化IP数据")

            # 获取有效IP
            valid_ips = self.ip_manager.get_valid_ips(line_code, 
                api_result["info"].get(line_code if self.config.RECORD_TYPE != "AAAA" else "DEF", []))
            
            if not valid_ips:
                raise ValueError(f"{line_code} 线路无有效 IP")

            # 提取IP地址
            new_ips = [ip["ip"] for ip in valid_ips]
            
            # 更新记录
            self._update_dns_records(domain, sub_domain, line_name, current_records, new_ips)
            
        except Exception as e:
            logging.error(f"处理记录失败 {masked_subdomain}.{masked_domain} {line_name}: {str(e)}")
            raise

    def _update_dns_records(self, domain, sub_domain, line_name, current_records, new_ips):
        """更新DNS记录的具体实现"""
        masked_domain = mask_domain(domain)
        masked_subdomain = mask_domain(sub_domain)
        
        try:
            if current_records:
                # 更新现有记录
                record_id = current_records[0]["recordId"]
                self.cloud.change_record(
                    domain, record_id, sub_domain, new_ips,
                    self.config.RECORD_TYPE, line_name, self.config.TTL
                )
                logging.info(f"更新记录成功 {masked_subdomain}.{masked_domain} {line_name} -> {new_ips}")
            else:
                # 创建新记录
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
            raise ValueError(f"记录操作失败: {str(e)}") from e

def main():
    """主函数"""
    try:
        # 初始化配置
        config = Config()
        
        # 验证配置
        config.validate()
        
        # 初始化华为云
        cloud = HuaWeiApi(
            config.SECRETID, 
            config.SECRETKEY, 
            config.REGION_HW if config.DNS_SERVER == "3.1" else None
        )
        
        # 初始化管理器
        ip_manager = IPManager(config)
        dns_manager = DNSManager(cloud, config, ip_manager)
        
        # 处理域名
        for domain, sub_domains in config.DOMAINS.items():
            if not isinstance(sub_domains, dict):
                logging.error(f"域名 {mask_domain(domain)} 配置格式错误")
                continue
                
            for sub_domain, lines in sub_domains.items():
                if not isinstance(lines, list):
                    logging.error(f"子域名 {mask_domain(sub_domain)} 配置格式错误")
                    continue
                    
                try:
                    dns_manager.update_records(domain, sub_domain, lines)
                except Exception as e:
                    logging.error(f"更新记录失败 {mask_domain(domain)}/{mask_domain(sub_domain)}: {str(e)}")
                    continue
                
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
