# Cybersecurity Homelab – Azure Honeypot with Log Analysis & Attack Map

## 📌 Overview
This project demonstrates the creation of a **honeypot** in Microsoft Azure, forwarding logs to **Microsoft Sentinel** via a **Log Analytics Workspace (LAW)**, enriching those logs with geographic information, and visualizing attacks in an interactive **attack map**.  

The lab simulates real-world **Security Operations Center (SOC)** workflows, including:
- Setting up vulnerable endpoints for threat detection
- Capturing and analyzing failed login attempts
- Using **KQL** (Kusto Query Language) for log analysis
- Integrating **geolocation data** for enrichment
- Creating a **visual attack map** in Sentinel

---

## 📚 Table of Contents
- [Tools & Technologies](#-tools--technologies)
- [Objectives](#-objectives)
- [Step-by-Step Walkthrough](#-step-by-step-walkthrough)
  - [Part 1 – Honeypot Setup](#part-1--honeypot-setup)
  - [Part 2 – Simulating Failed Logins](#part-2--simulating-failed-logins)
  - [Part 3 – Log Forwarding & KQL Queries](#part-3--log-forwarding--kql-queries)
  - [Part 4 – Log Enrichment (GeoIP Data)](#part-4--log-enrichment-geoip-data)
  - [Part 5 – Attack Map Creation](#part-5--attack-map-creation)
- [Results](#-results)
- [Skills Demonstrated](#-skills-demonstrated)
- [Next Steps](#-next-steps)

---

## 🛠 Tools & Technologies
- **Microsoft Azure**
- **Windows 10 Virtual Machine**
- **Azure Network Security Groups**
- **Windows Event Viewer**
- **Microsoft Sentinel**
- **Log Analytics Workspace (LAW)**
- **KQL** (Kusto Query Language)
- **GeoIP database** (CSV)
- **Sentinel Workbooks**

---

## 🎯 Objectives
1. Deploy a honeypot in Azure to attract and log malicious traffic.
2. Forward and store security logs in a central repository (LAW).
3. Analyze and filter logs using **KQL**.
4. Enrich log data with geolocation information.
5. Visualize attacks on an **interactive map** in Microsoft Sentinel.

---

## 🏗 Lab Architecture
![Lab Architecture](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Lab_Architecture.png)

---

## 📖 Step-by-Step Walkthrough

### Part 1 – Honeypot Setup
1. Navigate to [Azure Portal](https://portal.azure.com) → Search for **Virtual Machines**.
2. Create a **Windows 10 VM**  
   - Choose an appropriate size.  
   - Set and record **username/password**.  

   ![VM Creation](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/VM_Creation.png)

3. Go to the **Network Security Group** for your VM → Create an **inbound rule** that allows **all traffic**.
   
   ![NSG Rule](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/NSG_Rule.png)

4. Log in to the VM → Disable Windows Firewall:  
   ```
   Start → wf.msc → Properties → Turn Off (all profiles)
   ```

   ![Firewall Settings](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Firewall_Settings.png)

---

### Part 2 – Simulating Failed Logins
1. Attempt **3 failed logins** as `employee` (or another username).
2. Successfully log into the VM.
3. Open **Event Viewer** → Inspect **Security Logs**.
4. Locate **Event ID 4625** (Failed Logon).
   
   ![Event Viewer](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Event_Viewer.png)

---

### Part 3 – Log Forwarding & KQL Queries
1. Create a **Log Analytics Workspace (LAW)**.
2. Create a **Microsoft Sentinel instance** → Connect it to LAW.
3. Configure **Windows Security Events via AMA** connector.
4. Create the **Data Collection Rule (DCR)**.
5. Verify that VM logs are being forwarded.
6. Run a KQL query to filter failed logins:
   ```kql
   SecurityEvent
   | where EventID == 4625
   ```

   ![LAW Query Results](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/LAW_Query_Results.png)

---

### Part 4 – Log Enrichment (GeoIP Data)
1. Download **GeoIP CSV**:  
   [geoip-summarized.csv](https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/misc/geoip-summarized.csv)
   
2. In **Microsoft Defender** → Create a **Watchlist**:
   - **Name/Alias:** `geoip`  
   - **Source Type:** Local File  
   - **Search Key:** `network`  
   - **Rows before header:** 0  
   - Import (~54,000 rows)
   
   ![Watchlist Import](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Watchlist_Import.png)

3. Run enriched KQL query:
   ```kql
   let GeoIPDB_FULL = _GetWatchlist("geoip");
   let WindowsEvents = SecurityEvent
       | where EventID == 4625
       | order by TimeGenerated desc
       | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
   WindowsEvents
   ```

   ![Enriched Log Results](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Enriched_Log_Results.png)

---

### Part 5 – Attack Map Creation
1. In **Sentinel** → Create a **Workbook**.
2. Delete prepopulated elements.
3. Add a **Query** element → Paste provided JSON from `map.json`.
4. Configure map settings.
5. View real-time **geographic attack map**.
   
   ![Attack Map](SOC%20SIMULATOR%20%2B%20SIEM%20PICTURES/Attack_Map.png)

---

## 📊 Results
- Successfully simulated multiple failed login attempts.
- Captured and centralized logs in LAW.
- Queried logs using **KQL** to identify malicious activity.
- Enriched logs with **geographic data** from IP addresses.
- Visualized attacks on a **dynamic world map** in Microsoft Sentinel.

---

## 📚 Skills Demonstrated
- Cloud Infrastructure (Azure)
- Security Event Management (Microsoft Sentinel)
- KQL Query Writing
- Log Enrichment Techniques
- Cybersecurity Monitoring & Threat Intelligence

---

## 🚀 Next Steps
- Automate IP enrichment from a live API feed.
- Create Sentinel alert rules for Event ID 4625 spikes.
- Expand honeypot to Linux VMs.
- Integrate with external threat intelligence platforms.
