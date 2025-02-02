# Mail: tongdongdong@outlook.com
import sys
sys.path.append('./dns') 
import random
import time
import json
import requests
import os
import traceback
import logging
import sys
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
API = 'https://api.vvhan.com/tool/cf_ip'

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

def get_optimization_ip():
    """获取优化后的 IP 地址"""
    try:
        response = requests.get(API, timeout=10)
        response.raise_for_status()
        result = response.json()
        
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
        
        # 默认线路使用移动线路的IP
        if "CM" in formatted_result["info"]:
            formatted_result["info"]["DEF"] = formatted_result["info"]["CM"]
        
        return formatted_result
            
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

def mask_domain(domain):
    """隐藏域名信息，只显示首尾字符"""
    if not domain:
        return "***"
    if len(domain) <= 2:
        return "*" * len(domain)
    return f"{domain[0]}***{domain[-1]}"

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
            logging.error(f"获取记录失败: {masked_subdomain}.{masked_domain}")
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
        # 根据 DNS_SERVER 模式初始化华为云
        if DNS_SERVER not in ["3", "3.1"]:
            raise ValueError(f"不支持的 DNS_SERVER 值: {DNS_SERVER}，只支持 3 或 3.1")
            
        if DNS_SERVER == "3.1":
            cloud = HuaWeiApi(SECRETID, SECRETKEY, REGION_HW)
        else:  # DNS_SERVER == "3"
            cloud = HuaWeiApi(SECRETID, SECRETKEY)
            
    except Exception as e:
        logging.error(f"初始化华为云 DNS 失败: {str(e)}")
        return

    # 处理每个域名
    for domain, sub_domains in DOMAINS.items():
        if not isinstance(sub_domains, dict):
            logging.error(f"域名 {mask_domain(domain)} 配置格式错误")
            continue

        for sub_domain, lines in sub_domains.items():
            if not isinstance(lines, list):
                logging.error(f"子域名 {mask_domain(sub_domain)} 配置格式错误")
                continue

            logging.info(f"正在处理 {mask_domain(sub_domain)}.{mask_domain(domain)}")
            handle_dns_records(cloud, domain, sub_domain, lines)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("用户中断执行")
    except Exception as e:
        logging.error(f"程序异常: {str(e)}")
        logging.debug(traceback.format_exc())
