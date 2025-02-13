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
    """获取优化后的 IP 地址"""
    try:
        if API in [API_1, API_2]:  # hostmonit 和 345673 API
            headers = {'Content-Type': 'application/json'}
            data = {"key": SECRETKEY, "type": "v4" if RECORD_TYPE == "A" else "v6"}
            response = requests.post(API, json=data, headers=headers, timeout=10)
        else:  # wetest 和 vvhan API
            response = requests.get(API, timeout=10)
            
        response.raise_for_status()
        result = response.json()
        
        if API == API_3:  # wetest API
            if not result.get("status") or result.get("code") != 200 or "info" not in result:
                logging.error(f"API 返回异常数据: {json.dumps(result)}")
                return None
                
            # wetest API 只处理 IPv4
            if RECORD_TYPE != "A":
                logging.error("wetest API 只支持 IPv4 地址")
                return None
                
            formatted_result = {
                "code": 200,
                "info": {}
            }
            
            # 处理每个运营商的数据
            for isp in ["CM", "CU", "CT"]:
                if isp in result["info"] and result["info"][isp]:
                    # 按延迟排序
                    sorted_ips = sorted(result["info"][isp], 
                                     key=lambda x: x.get("delay", float('inf')))
                    # 取延迟最低的前 AFFECT_NUM 个IP
                    best_ips = sorted_ips[:AFFECT_NUM]
                    formatted_result["info"][isp] = [{"ip": ip["address"]} for ip in best_ips]
                    
                    # 记录选中IP的延迟
                    for ip in best_ips:
                        logging.info(f"{isp} 线路选中IP: {ip['address']}, "
                                   f"延迟: {ip.get('delay')}ms")
            
            # 默认线路使用移动线路的IP
            if "CM" in formatted_result["info"]:
                formatted_result["info"]["DEF"] = formatted_result["info"]["CM"]
            elif formatted_result["info"]:
                first_available = next(iter(formatted_result["info"].values()))
                formatted_result["info"]["DEF"] = first_available
                logging.info("默认线路使用其他可用线路的IP")
            
            return formatted_result
            
        elif API == API_4:  # vvhan API
            if not result.get("success") or "data" not in result:
                logging.error(f"API 返回异常数据: {json.dumps(result)}")
                return None
                
            ip_data = result["data"]["v4" if RECORD_TYPE == "A" else "v6"]
            
            # 为每个运营商选择延迟最低的IP
            formatted_result = {
                "code": 200,
                "info": {}
            }
            
            for isp in ["CM", "CU", "CT"]:
                if isp in ip_data and ip_data[isp]:
                    # 按延迟排序，选择延迟最低的IP
                    sorted_ips = sorted(ip_data[isp], key=lambda x: x.get("latency", float('inf')))
                    # 取延迟最低的前 AFFECT_NUM 个IP
                    best_ips = sorted_ips[:AFFECT_NUM]
                    formatted_result["info"][isp] = [{"ip": ip["ip"]} for ip in best_ips]
                    
                    # 记录选中IP的延迟
                    for ip in best_ips:
                        logging.info(f"{isp} 线路选中IP: {ip['ip']}, "
                                   f"延迟: {ip.get('latency', 'unknown')}ms")
            
            # 默认线路使用移动线路的IP
            if "CM" in formatted_result["info"]:
                formatted_result["info"]["DEF"] = formatted_result["info"]["CM"]
            elif formatted_result["info"]:
                first_available = next(iter(formatted_result["info"].values()))
                formatted_result["info"]["DEF"] = first_available
                logging.info("默认线路使用其他可用线路的IP")
            
            return formatted_result
            
        else:  # 其他 API
            if result.get("code") != 200 or "info" not in result:
                logging.error(f"API 返回异常数据: {json.dumps(result)}")
                return None
                
            return result
            
    except requests.exceptions.RequestException as e:
        logging.error(f"请求优化 IP API 失败: {str(e)}")
    except json.JSONDecodeError:
        logging.error("API 返回非 JSON 数据")
    except Exception as e:
        logging.error(f"获取优化 IP 异常: {str(e)}")
        logging.debug(traceback.format_exc())
    return None

def validate_ips(ip_list):
    """验证 IP 列表有效性"""
    return [ip for ip in ip_list if isinstance(ip, dict) and "ip" in ip]

def handle_dns_records(cloud, domain, sub_domain, line_config):
    """处理 DNS 记录的核心逻辑"""
    # 用于日志显示的掩码域名
    masked_domain = mask_domain(domain)
    masked_subdomain = mask_domain(sub_domain)
    
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
        new_ips = [ip["ip"] for ip in valid_ips[:AFFECT_NUM]]
        
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
