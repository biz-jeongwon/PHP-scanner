import requests
from bs4 import BeautifulSoup
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

print_lock = Lock()

def search_wordpress_plugins(keyword, pages, max_plugins=20):
    plugin_links = []
    for page in range(1, int(pages) + 1):
        search_url = f"https://wordpress.org/plugins/search/{keyword}/page/{page}"
        response = requests.get(search_url)
        soup = BeautifulSoup(response.text, "html.parser")

        for h3 in soup.select("h3.entry-title")[:max_plugins]:
            a_tag = h3.find("a")
            if a_tag and a_tag.get("href"):
                plugin_links.append(a_tag["href"])
    return plugin_links

def download_plugin_zip(plugin_url, download_dir="plugins-wp"):
    plugin_slug = plugin_url.rstrip('/').split('/')[-1]
    zip_url = f"https://downloads.wordpress.org/plugin/{plugin_slug}.latest-stable.zip"

    os.makedirs(download_dir, exist_ok=True)
    zip_path = os.path.join(download_dir, f"{plugin_slug}.zip")

    try:
        with print_lock:
            print(f"{Colors.OKBLUE}[+] Downloading {plugin_slug}...{Colors.RESET}", flush=True)
        response = requests.get(zip_url)
        if response.status_code == 200:
            with open(zip_path, "wb") as f:
                f.write(response.content)
            with print_lock:
                print(f"{Colors.OKGREEN}[OK] Saved to: {zip_path}{Colors.RESET}", flush=True)
        else:
            with print_lock:
                print(f"{Colors.FAIL}[X] Failed to download {plugin_slug} (Status: {response.status_code}){Colors.RESET}", flush=True)
    except Exception as e:
        with print_lock:
            print(f"{Colors.FAIL}[X] Error downloading {plugin_slug}: {e}{Colors.RESET}", flush=True)

def extract_and_cleanup_zip_files(directory="plugins-wp"):
    print(f"{Colors.BOLD}\n[*] Extracting zip files and cleaning up...{Colors.RESET}", flush=True)
    for filename in os.listdir(directory):
        if filename.endswith(".zip"):
            zip_path = os.path.join(directory, filename)
            extract_path = os.path.join(directory, filename.replace(".zip", ""))

            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                os.remove(zip_path)
                with print_lock:
                    print(f"{Colors.OKGREEN}[OK] Extracted and deleted: {filename}{Colors.RESET}", flush=True)
            except zipfile.BadZipFile:
                with print_lock:
                    print(f"{Colors.FAIL}[X] Bad zip file: {filename}{Colors.RESET}", flush=True)
            except Exception as e:
                with print_lock:
                    print(f"{Colors.FAIL}[X] Failed to extract {filename}: {e}{Colors.RESET}", flush=True)

def main():
    keyword_input = input(f"{Colors.BOLD}[?] Enter plugin keywords (space-separated): {Colors.RESET}")
    pages = input(f"{Colors.BOLD}[?] Enter number of pages to search per keyword: {Colors.RESET}")

    keywords = keyword_input.strip().split()

    for keyword in keywords:
        print(f"\n{Colors.HEADER}[*] Searching for keyword: '{keyword}'...{Colors.RESET}", flush=True)
        plugin_urls = search_wordpress_plugins(keyword, pages)

        if not plugin_urls:
            print(f"{Colors.WARNING}[X] No plugins found for '{keyword}'.{Colors.RESET}", flush=True)
            continue

        print(f"{Colors.BOLD}[!] Downloading {len(plugin_urls)} plugins for '{keyword}'...{Colors.RESET}", flush=True)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(download_plugin_zip, url) for url in plugin_urls]
            for future in as_completed(futures):
                pass

    extract_and_cleanup_zip_files()

if __name__ == "__main__":
    main()