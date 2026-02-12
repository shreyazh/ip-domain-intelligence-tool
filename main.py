import streamlit as st
import socket
import re
import dns.resolver
import dns.reversename
import requests
from urllib.parse import urlparse

st.set_page_config(page_title="IP ↔ Domain Intelligence Tool", page_icon="🐽")
st.title("🐽 IP ↔ Domain Intelligence Tool")

# Utilities
def clean_domain_input(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.hostname

def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

# Domain → IP
def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        return f"DNS resolution failed: {e}"

# IP → Reverse DNS (PTR)
def reverse_dns_lookup(ip):
    try:
        reverse_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        return [rdata.to_text() for rdata in answers]
    except Exception as e:
        return f"No PTR record found: {e}"

# IP → Hosted Domains (reverse IP API)
def reverse_ip_lookup(ip):
    try:
        # free API (rate limited)
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.text.strip()
            if "error" in data.lower():
                return "no hosted domains found or API limit reached."
            return data.split("\n")
        else:
            return f"API Error: {response.status_code}"
    except Exception as e:
        return f"rev IP lookup failed: {e}"

# UI
user_input = st.text_input("enter Domain or IP Address")

if st.button("lookup"):

    if not user_input.strip():
        st.warning("enter a valid domain or IP.")
        st.stop()

    user_input = user_input.strip()

    # ---------------- ip ----------------
    if is_valid_ip(user_input):

        st.subheader("reverse DNS (ptr record)")
        ptr_result = reverse_dns_lookup(user_input)

        if isinstance(ptr_result, list):
            for item in ptr_result:
                st.success(item)
        else:
            st.error(ptr_result)

        st.subheader("hosted domains on this IP")
        reverse_ip_result = reverse_ip_lookup(user_input)

        if isinstance(reverse_ip_result, list):
            for domain in reverse_ip_result:
                st.write(domain)
        else:
            st.error(reverse_ip_result)

    # ---------------- domain ----------------
    else:
        domain = clean_domain_input(user_input)
        if not domain:
            st.error("Invalid domain format.")
        else:
            st.subheader("A Records (IP addresses)")
            ip_result = resolve_domain(domain)

            if isinstance(ip_result, list):
                for ip in ip_result:
                    st.success(ip)
            else:
                st.error(ip_result)
