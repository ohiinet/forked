# Mail: tongdongdong@outlook.com
import random
import time
import json
import requests
import os
import traceback
import logging
import sys
from dns.qCloud import QcloudApiv3  # QcloudApiv3 DNSPod 的 API 更新了 github@z0z0r4
from dns.aliyun import AliApi
from dns.huawei import HuaWeiApi

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# 环境变量配置
def get_env_or_raise(key):
    value = os.getenv(key)
    if not value:
        raise ValueError(f"环境变量 {key} 未设置")
    return value

try:
    KEY = get_env_or_raise("KEY")
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
DNS_SERVER = os.getenv("DNS_SERVER", "3.1")  # 使用字符串标识服务商
TTL = int(os.getenv("TTL", 300))  # 默认 TTL 600 秒
RECORD_TYPE = sys.argv[1] if len(sys.argv) >= 2 else "A"  # 记录类型 A/AAAA
REGION_HW = 'cn-east-3'

# API 配置
API_1 = 'https://api.hostmonit.com/get_optimization_ip'
API_2 = 'https://api.345673.xyz/get_data'
API_3 = 'https://www.wetest.vip/api/cf2dns/get_cloudflare_ip'

# 自定义 IP 配置
def parse_custom_ips(ip_str):
    return [{"ip": ip.strip()} for ip in ip_str.split(',') if ip.strip()]

if RECORD_TYPE == "A":
    API = API_3
    self_cm_cfips = ""
    self_cu_cfips = ""
    self_ct_cfips = "104.19.37.227, 8.20.125.2, 104.19.138.18"
    self_def_cfips = ""
else:
    API = API_3
    self_cm_cfips = ""
    self_cu_cfips = ""
    self_ct_cfips = ""
    self_def_cfips = "2606:4700:91b8::, 2a06:98c1:56::"

self_cm_cfips_list = parse_custom_ips(self_cm_cfips)
self_cu_cfips_list = parse_custom_ips(self_cu_cfips)
self_ct_cfips_list = parse_custom_ips(self_ct_cfips)
self_def_cfips_list = parse_custom_ips(self_def_cfips)

# DNS 服务商映射表
DNS_PROVIDERS = {
    "1": QcloudApiv3,
    "2": AliApi,
    "3": HuaWeiApi,
    "3.1": HuaWeiApi  # 华为云特殊版本
}

# 核心功能函数
def get_optimization_ip():
    """获取优化后的 IP 地址"""
    try:
        headers = {'Content-Type': 'application/json'}
        data = {"key": KEY, "type": "v4" if RECORD_TYPE == "A" else "v6"}
        
        response = requests.post(API, json=data, headers=headers, timeout=10)
        response.raise_for_status()
        
        result = response.json()
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
    return None

def validate_ips(ip_list):
    """验证 IP 列表有效性"""
    return [ip for ip in ip_list if isinstance(ip, dict) and "ip" in ip]

def concatenate_ips(c_info, s_info):
    """合并 IP 地址并去重"""
    new_ips = []
    c_info_copy = c_info.copy()
    
    while c_info_copy:
        idx = random.randint(0, len(c_info_copy) - 1)
        current_ip = c_info_copy.pop(idx)
        
        # 检查是否已存在
        if not any(current_ip["ip"] == record.get("value") for record in s_info):
            new_ips.append(current_ip["ip"])
    
    return new_ips[:AFFECT_NUM]  # 最多返回 AFFECT_NUM 个 IP

def handle_dns_records(cloud, domain, sub_domain, line_config):
    """处理 DNS 记录的核心逻辑"""
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
            if DNS_SERVER == "1" and records.get("code") != 0:
                raise Exception(records.get("message", "获取记录失败"))
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

        # 计算需要变更的记录数
        existing_num = len(current_records)
        create_num = AFFECT_NUM - existing_num

        # 记录操作逻辑
        try:
            if create_num == 0:  # 更新现有记录
                for record in current_records:
                    if not valid_ips:
                        break
                    new_ip = valid_ips.pop(0)["ip"]
                    cloud.change_record(domain, record["recordId"], sub_domain, new_ip, RECORD_TYPE, line_name, TTL)
                    logging.info(f"更新记录成功 {domain} {sub_domain} {line_name} -> {new_ip}")

            elif create_num > 0:  # 创建新记录
                for _ in range(create_num):
                    if not valid_ips:
                        break
                    new_ip = valid_ips.pop(0)["ip"]
                    cloud.create_record(domain, sub_domain, new_ip, RECORD_TYPE, line_name, TTL)
                    logging.info(f"创建记录成功 {domain} {sub_domain} {line_name} -> {new_ip}")

            else:  # 删除多余记录
                for record in current_records[:abs(create_num)]:
                    cloud.del_record(domain, record["recordId"])
                    logging.info(f"删除多余记录 {domain} {sub_domain} {line_name}")

        except Exception as e:
            logging.error(f"记录操作失败: {str(e)}")
            logging.debug(traceback.format_exc())

def main():
    """主函数"""
    # 初始化云服务商
    provider_class = DNS_PROVIDERS.get(DNS_SERVER)
    if not provider_class:
        logging.error(f"不支持的 DNS 服务商配置: {DNS_SERVER}")
        return

    try:
        if DNS_SERVER == "3.1":
            cloud = provider_class(SECRETID, SECRETKEY, REGION_HW, is_collection=True)
        elif DNS_SERVER == "2":
            cloud = provider_class(SECRETID, SECRETKEY, REGION_ALI)
        else:
            cloud = provider_class(SECRETID, SECRETKEY)
    except Exception as e:
        logging.error(f"初始化 DNS 服务商失败: {str(e)}")
        return

    # 处理每个域名
    for domain, sub_domains in DOMAINS.items():
        if not isinstance(sub_domains, dict):
            logging.error(f"域名 {domain} 配置格式错误")
            continue

        for sub_domain, lines in sub_domains.items():
            if not isinstance(lines, list):
                logging.error(f"子域名 {sub_domain} 配置格式错误")
                continue

            logging.info(f"正在处理 {sub_domain}.{domain}")
            handle_dns_records(cloud, domain, sub_domain, lines)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("用户中断执行")
    except Exception as e:
        logging.error(f"程序异常: {str(e)}")
        logging.debug(traceback.format_exc())
